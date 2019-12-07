/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_epoll.c
 *
 * Implementation of system call "epoll_create", "epoll_create1", "epoll_ctl"
 * and "epoll_wait".
 */

#include <errno.h>
#include <linux/eventpoll.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>

/* Avoid duplicated definitions */
#ifndef EPOLLIN
#define EPOLLIN     0x001
#define EPOLLOUT    0x004
#define EPOLLRDNORM 0x040
#define EPOLLWRNORM 0x100
#define EPOLLERR    0x008
#define EPOLLHUP    0x010
#define EPOLLRDHUP  0x2000
#endif

/* TODO: 1024 handles/FDs is a small number for high-load servers (e.g., Linux has ~3M) */
#define MAX_EPOLL_HANDLES 1024

struct shim_mount epoll_builtin_fs;

struct shim_epoll_item {
    FDTYPE fd;
    __u64 data;
    unsigned int events;
    unsigned int revents;
    struct shim_handle* handle;      /* reference to monitored object (socket, pipe, file, etc) */
    struct shim_handle* epoll;       /* reference to epoll object that monitors handle object */
    LIST_TYPE(shim_epoll_item) list; /* list of shim_epoll_items, used by epoll object (via `fds`) */
    LIST_TYPE(shim_epoll_item) back; /* list of epolls, used by handle object (via `epolls`) */
};

int shim_do_epoll_create1(int flags) {
    if ((flags & ~EPOLL_CLOEXEC))
        return -EINVAL;

    struct shim_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    struct shim_epoll_handle* epoll = &hdl->info.epoll;

    hdl->type = TYPE_EPOLL;
    set_handle_fs(hdl, &epoll_builtin_fs);
    epoll->maxfds      = MAX_EPOLL_HANDLES;
    epoll->npals       = 0;
    epoll->nread       = 0;
    epoll->nwaiters    = 0;
    epoll->pal_handles = malloc(sizeof(PAL_HANDLE) * MAX_EPOLL_HANDLES);
    create_event(&epoll->event);
    INIT_LISTP(&epoll->fds);

    int vfd = set_new_fd_handle(hdl, (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0, NULL);
    put_handle(hdl);
    return vfd;
}

/* the 'size' argument of epoll_create is not used */
int shim_do_epoll_create(int size) {
    if (size < 0)
        return -EINVAL;

    return shim_do_epoll_create1(0);
}

static void update_epoll(struct shim_epoll_handle* epoll) {
    struct shim_epoll_item* tmp;
    epoll->npals = 0;
    epoll->nread = 0;

    LISTP_FOR_EACH_ENTRY(tmp, &epoll->fds, list) {
        if (!tmp->handle->pal_handle)
            continue;

        debug("found handle %p (pal handle %p) from epoll handle %p\n", tmp->handle,
              tmp->handle->pal_handle, epoll);

        epoll->pal_handles[epoll->npals++] = tmp->handle->pal_handle;
        if (tmp->handle->acc_mode & MAY_READ)
            epoll->nread++;
    }

    /* if other threads are currently waiting on epoll_wait(), send a signal to update their
     * epoll items (note that we send nwaiters number of signals -- to each waiting thread) */
    if (epoll->nwaiters)
        set_event(&epoll->event, epoll->nwaiters);
}

int delete_from_epoll_handles(struct shim_handle* handle) {
    /* handle may be registered in several epolls, delete it from all of them via handle->epolls */
    while (1) {
        /* first, get any epoll-item from this handle (via `back` list) and delete it from `back` */
        lock(&handle->lock);
        if (LISTP_EMPTY(&handle->epolls)) {
            unlock(&handle->lock);
            break;
        }

        struct shim_epoll_item* epoll_item =
            LISTP_FIRST_ENTRY(&handle->epolls, struct shim_epoll_item, back);

        LISTP_DEL(epoll_item, &handle->epolls, back);
        unlock(&handle->lock);

        /* second, get epoll to which this epoll-item belongs to, and remove epoll-item from
         * epoll's `fds` list, and trigger update_epoll() to re-populate pal_handles */
        struct shim_handle* hdl         = epoll_item->epoll;
        struct shim_epoll_handle* epoll = &hdl->info.epoll;

        lock(&hdl->lock);
        LISTP_DEL(epoll_item, &epoll->fds, list);
        update_epoll(epoll);
        unlock(&hdl->lock);

        /* finally, free this epoll-item and put reference to epoll it belonged to
         * (note that epoll is deleted only after all handles referring to this epoll are
         * deleted from it, so we keep track of this via refcounting) */
        free(epoll_item);
        put_handle(hdl);
    }

    return 0;
}

int shim_do_epoll_ctl(int epfd, int op, int fd, struct __kernel_epoll_event* event) {
    struct shim_thread* cur = get_cur_thread();
    int ret                 = 0;

    if (epfd == fd)
        return -EINVAL;

    struct shim_handle* epoll_hdl = get_fd_handle(epfd, NULL, cur->handle_map);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    struct shim_epoll_handle* epoll = &epoll_hdl->info.epoll;
    struct shim_epoll_item* epoll_item;

    lock(&epoll_hdl->lock);

    switch (op) {
        case EPOLL_CTL_ADD: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    ret = -EEXIST;
                    goto out;
                }
            }

            struct shim_handle* hdl = get_fd_handle(fd, NULL, cur->handle_map);
            if (!hdl) {
                ret = -EBADF;
                goto out;
            }
            /* note that pipe and socket may not have pal_handle yet (e.g. before bind()) */
            if ((hdl->type != TYPE_PIPE && hdl->type != TYPE_SOCK) || !hdl->pal_handle) {
                ret = -EPERM;
                put_handle(hdl);
                goto out;
            }
            if (epoll->npals == MAX_EPOLL_HANDLES) {
                ret = -ENOSPC;
                put_handle(hdl);
                goto out;
            }

            debug("add handle %p to epoll handle %p\n", hdl, epoll);

            epoll_item             = malloc(sizeof(struct shim_epoll_item));
            epoll_item->fd         = fd;
            epoll_item->events     = event->events;
            epoll_item->data       = event->data;
            epoll_item->revents    = 0;
            epoll_item->handle     = hdl;
            epoll_item->epoll      = epoll_hdl;
            get_handle(epoll_hdl);

            /* register hdl (corresponding to FD) in epoll (corresponding to EPFD):
             * - bind hdl to epoll-item via the `back` list
             * - bind epoll-item to epoll via the `list` list */
            lock(&hdl->lock);
            INIT_LIST_HEAD(epoll_item, back);
            LISTP_ADD_TAIL(epoll_item, &hdl->epolls, back);
            unlock(&hdl->lock);

            /* note that we already grabbed epoll_hdl->lock so can safely update epoll */
            INIT_LIST_HEAD(epoll_item, list);
            LISTP_ADD_TAIL(epoll_item, &epoll->fds, list);

            put_handle(hdl);
            goto update;
        }

        case EPOLL_CTL_MOD: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    epoll_item->events = event->events;
                    epoll_item->data   = event->data;
                    goto update;
                }
            }

            ret = -ENOENT;
            goto out;
        }

        case EPOLL_CTL_DEL: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    struct shim_handle* hdl = epoll_item->handle;

                    /* unregister hdl (corresponding to FD) in epoll (corresponding to EPFD):
                     * - unbind hdl from epoll-item via the `back` list
                     * - unbind epoll-item from epoll via the `list` list */
                    lock(&hdl->lock);
                    LISTP_DEL(epoll_item, &hdl->epolls, back);
                    unlock(&hdl->lock);

                    /* note that we already grabbed epoll_hdl->lock so can safely update epoll */
                    LISTP_DEL(epoll_item, &epoll->fds, list);

                    put_handle(epoll_hdl);
                    free(epoll_item);
                    goto update;
                }
            }

            ret = -ENOENT;
            goto out;
        }

        default:
            ret = -EINVAL;
            goto out;
    }

update:
    update_epoll(epoll);
out:
    unlock(&epoll_hdl->lock);
    put_handle(epoll_hdl);
    return ret;
}

int shim_do_epoll_wait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                       int timeout_ms) {
    if (maxevents <= 0)
        return -EINVAL;

    if (!events || test_user_memory(events, sizeof(*events) * maxevents, true))
        return -EFAULT;

    struct shim_handle* epoll_hdl = get_fd_handle(epfd, NULL, NULL);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    struct shim_epoll_handle* epoll = &epoll_hdl->info.epoll;
    bool need_update = false;

    lock(&epoll_hdl->lock);

    int npals = epoll->npals;
    while (npals) {
        /* wait on epoll's PAL handles + one "event" handle that signals epoll updates */
        PAL_HANDLE* pal_handles = malloc((npals + 1) * sizeof(PAL_HANDLE));
        if (!pal_handles)
            return -ENOMEM;

        memcpy(pal_handles, epoll->pal_handles, npals * sizeof(PAL_HANDLE));
        pal_handles[npals] = epoll->event.event;

        epoll->nwaiters++;  /* mark epoll as being waited on (so epoll-update signal is sent) */
        unlock(&epoll_hdl->lock);

        PAL_NUM pal_timeout = timeout_ms == -1 ? NO_TIMEOUT : (PAL_NUM)timeout_ms * 1000;
        if (!epoll->nread) {
            /* special case: epoll doesn't contain a single handle with MAY_READ, thus there are
             * only write events possible, and for this we don't wait but return immediately
             * TODO: this is an ugly corner case which may backfire */
            pal_timeout = 0;
        }

        /* TODO: This is highly inefficient, since DkObjectsWaitAny returns only one (random)
         *       handle out of the whole array of handles-waiting-for-events. We must replace
         *       this with DkObjectsWaitEvents(). */
        PAL_HANDLE polled = DkObjectsWaitAny(npals + 1, pal_handles, pal_timeout);

        lock(&epoll_hdl->lock);
        epoll->nwaiters--;
        free(pal_handles);

        if (polled == epoll->event.event) {
            wait_event(&epoll->event);
            npals = epoll->npals; /* epoll was updated, probably npals is new */
            continue;
        }

        PAL_STREAM_ATTR attr;
        if (!polled || !DkStreamAttributesQueryByHandle(polled, &attr))
            break;

        struct shim_epoll_item* epoll_item = NULL;
        struct shim_epoll_item* tmp;
        LISTP_FOR_EACH_ENTRY(tmp, &epoll->fds, list) {
            if (polled == tmp->handle->pal_handle) {
                epoll_item = tmp;
                break;
            }
        }

        /* found epoll item that was polled, update its revents according to attr */
        assert(epoll_item);
        if (attr.disconnected) {
            epoll_item->revents |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;
            epoll_item->handle   = NULL;
            need_update        = true; /* handle disconnected, need to remove from epoll list */
        }
        if (attr.readable)
            epoll_item->revents |= EPOLLIN | EPOLLRDNORM;
        if (attr.writable)
            epoll_item->revents |= EPOLLOUT | EPOLLWRNORM;

        npals = 0; /* to exit the while loop */
    }

    /* update user-supplied events array with all events detected till now on epoll */
    int nevents = 0;
    struct shim_epoll_item* epoll_item;
    LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
        if (nevents == maxevents)
            break;

        unsigned int monitored_events = epoll_item->events | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
        if (epoll_item->revents & monitored_events) {
            events[nevents].events = epoll_item->revents & monitored_events;
            events[nevents].data   = epoll_item->data;
            epoll_item->revents &= ~epoll_item->events; /* informed user about revents, may clear */
            nevents++;
        }
    }

    /* some handles were disconnected and thus must be removed from the epoll list */
    if (need_update)
        update_epoll(epoll);

    unlock(&epoll_hdl->lock);
    put_handle(epoll_hdl);
    return nevents;
}

int shim_do_epoll_pwait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                        int timeout_ms, const __sigset_t* sigmask, size_t sigsetsize) {
    __UNUSED(sigmask);
    __UNUSED(sigsetsize);
    int ret = shim_do_epoll_wait(epfd, events, maxevents, timeout_ms);
    return ret;
}

static int epoll_close(struct shim_handle* hdl) {
    struct shim_epoll_handle* epoll = &hdl->info.epoll;

    free(epoll->pal_handles);
    destroy_event(&epoll->event);

    /* epoll is finally closed only after all FDs referring to it have been closed */
    assert(LISTP_EMPTY(&epoll->fds));
    return 0;
}

struct shim_fs_ops epoll_fs_ops = {
    .close = &epoll_close,
};

struct shim_mount epoll_builtin_fs = {
    .type   = "epoll",
    .fs_ops = &epoll_fs_ops,
};

BEGIN_CP_FUNC(epoll_item) {
    __UNUSED(size);
    assert(size == sizeof(LISTP_TYPE(shim_epoll_item)));

    LISTP_TYPE(shim_epoll_item)* old_list = (LISTP_TYPE(shim_epoll_item)*)obj;
    LISTP_TYPE(shim_epoll_item)* new_list = (LISTP_TYPE(shim_epoll_item)*)objp;
    struct shim_epoll_item* epoll_item;

    debug("checkpoint epoll: %p -> %p (base = 0x%08lx)\n", old_list, new_list, base);

    INIT_LISTP(new_list);

    LISTP_FOR_EACH_ENTRY(epoll_item, old_list, list) {
        ptr_t off = ADD_CP_OFFSET(sizeof(struct shim_epoll_item));

        struct shim_epoll_item* new_epoll_item = (struct shim_epoll_item*)(base + off);

        new_epoll_item->fd         = epoll_item->fd;
        new_epoll_item->events     = epoll_item->events;
        new_epoll_item->data       = epoll_item->data;
        new_epoll_item->revents    = epoll_item->revents;

        LISTP_ADD(new_epoll_item, new_list, list);

        DO_CP(handle, epoll_item->handle, &new_epoll_item->handle);
    }

    ADD_CP_FUNC_ENTRY((ptr_t)objp - base);
}
END_CP_FUNC(epoll_item)

BEGIN_RS_FUNC(epoll_item) {
    __UNUSED(offset);
    LISTP_TYPE(shim_epoll_item)* list = (void*)(base + GET_CP_FUNC_ENTRY());
    struct shim_epoll_item* epoll_item;

    CP_REBASE(*list);

    LISTP_FOR_EACH_ENTRY(epoll_item, list, list) {
        CP_REBASE(epoll_item->handle);
        CP_REBASE(epoll_item->back);
        CP_REBASE(epoll_item->list);

        DEBUG_RS("fd=%d,path=%s,type=%s,uri=%s", epoll_item->fd, qstrgetstr(&epoll_item->handle->path),
                 epoll_item->handle->fs_type, qstrgetstr(&epoll_item->handle->uri));
    }
}
END_RS_FUNC(epoll_item)
