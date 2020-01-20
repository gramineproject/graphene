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
    uint64_t data;
    unsigned int events;
    unsigned int revents;
    bool connected;
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

    PAL_HANDLE* pal_handles = malloc(sizeof(*pal_handles) * MAX_EPOLL_HANDLES);
    if (!pal_handles) {
        put_handle(hdl);
        return -ENOMEM;
    }

    struct shim_epoll_handle* epoll = &hdl->info.epoll;

    hdl->type = TYPE_EPOLL;
    set_handle_fs(hdl, &epoll_builtin_fs);
    epoll->maxfds      = MAX_EPOLL_HANDLES;
    epoll->pal_cnt     = 0;
    epoll->waiter_cnt  = 0;
    epoll->pal_handles = pal_handles;
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

/* lock of shim_handle enclosing this epoll should be held while calling this function */
static void update_epoll(struct shim_epoll_handle* epoll) {
    assert(locked(&container_of(epoll, struct shim_handle, info.epoll)->lock));

    struct shim_epoll_item* tmp;
    epoll->pal_cnt = 0;

    LISTP_FOR_EACH_ENTRY(tmp, &epoll->fds, list) {
        if (!tmp->connected || !tmp->handle || !tmp->handle->pal_handle)
            continue;

        assert(epoll->pal_cnt < MAX_EPOLL_HANDLES);
        epoll->pal_handles[epoll->pal_cnt++] = tmp->handle->pal_handle;
    }

    /* if other threads are currently waiting on epoll_wait(), send a signal to update their
     * epoll items (note that we send waiter_cnt number of signals -- to each waiting thread) */
    if (epoll->waiter_cnt)
        set_event(&epoll->event, epoll->waiter_cnt);
}

void delete_from_epoll_handles(struct shim_handle* handle) {
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
}

int shim_do_epoll_ctl(int epfd, int op, int fd, struct __kernel_epoll_event* event) {
    struct shim_thread* cur = get_cur_thread();
    int ret                 = 0;

    if (epfd == fd)
        return -EINVAL;

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD)
        if (!event || test_user_memory(event, sizeof(*event), false)) {
            /* surprisingly, man(epoll_ctl) does not specify EFAULT if event is invalid so
             * we re-use EINVAL; also note that EPOLL_CTL_DEL ignores event completely */
            return -EINVAL;
        }

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
            if (hdl->type != TYPE_PIPE && hdl->type != TYPE_SOCK && hdl->type != TYPE_EVENTFD) {
                ret = -EPERM;
                put_handle(hdl);
                goto out;
            }
            if (epoll->pal_cnt == MAX_EPOLL_HANDLES) {
                ret = -ENOSPC;
                put_handle(hdl);
                goto out;
            }

            epoll_item = malloc(sizeof(struct shim_epoll_item));
            if (!epoll_item) {
                ret = -ENOMEM;
                put_handle(hdl);
                goto out;

            }

            debug("add fd %d (handle %p) to epoll handle %p\n", fd, hdl, epoll);
            epoll_item->fd        = fd;
            epoll_item->events    = event->events;
            epoll_item->data      = event->data;
            epoll_item->revents   = 0;
            epoll_item->handle    = hdl;
            epoll_item->epoll     = epoll_hdl;
            epoll_item->connected = true;
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

            update_epoll(epoll);
            break;
        }

        case EPOLL_CTL_MOD: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    epoll_item->events = event->events;
                    epoll_item->data   = event->data;

                    debug("modified fd %d at epoll handle %p\n", fd, epoll);
                    update_epoll(epoll);
                    goto out;
                }
            }

            ret = -ENOENT;
            break;
        }

        case EPOLL_CTL_DEL: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    struct shim_handle* hdl = epoll_item->handle;
                    debug("delete fd %d (handle %p) from epoll handle %p\n", fd, hdl, epoll);

                    /* unregister hdl (corresponding to FD) in epoll (corresponding to EPFD):
                     * - unbind hdl from epoll-item via the `back` list
                     * - unbind epoll-item from epoll via the `list` list */
                    lock(&hdl->lock);
                    LISTP_DEL(epoll_item, &hdl->epolls, back);
                    unlock(&hdl->lock);

                    /* note that we already grabbed epoll_hdl->lock so we can safely update epoll */
                    LISTP_DEL(epoll_item, &epoll->fds, list);

                    put_handle(epoll_hdl);
                    free(epoll_item);

                    update_epoll(epoll);
                    goto out;
                }
            }

            ret = -ENOENT;
            break;
        }

        default:
            ret = -EINVAL;
            break;
    }

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

    /* loop to retry on interrupted epoll waits (due to epoll being concurrently updated) */
    while (1) {
        /* wait on epoll's PAL handles + one "event" handle that signals epoll updates */
        PAL_HANDLE* pal_handles = malloc((epoll->pal_cnt + 1) * sizeof(PAL_HANDLE));
        if (!pal_handles) {
            unlock(&epoll_hdl->lock);
            put_handle(epoll_hdl);
            return -ENOMEM;
        }

        /* allocate one memory region to hold two PAL_FLG arrays: events and revents */
        PAL_FLG* pal_events = malloc((epoll->pal_cnt + 1) * sizeof(PAL_FLG) * 2);
        if (!pal_events) {
            free(pal_handles);
            unlock(&epoll_hdl->lock);
            put_handle(epoll_hdl);
            return -ENOMEM;
        }
        PAL_FLG* ret_events = pal_events + (epoll->pal_cnt + 1);

        /* populate pal_events with read/write events from user-supplied epoll items */
        int pal_cnt = 0;
        struct shim_epoll_item* epoll_item;
        LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
            if (!epoll_item->handle || !epoll_item->handle->pal_handle)
                continue;

            pal_handles[pal_cnt] = epoll_item->handle->pal_handle;
            pal_events[pal_cnt]  = (epoll_item->events & (EPOLLIN | EPOLLRDNORM)) ? PAL_WAIT_READ  : 0;
            pal_events[pal_cnt] |= (epoll_item->events & (EPOLLOUT | EPOLLWRNORM)) ? PAL_WAIT_WRITE : 0;
            ret_events[pal_cnt]  = 0;
            pal_cnt++;
        }

        /* populate "event" handle so it waits on read (meaning epoll-update signal arrived);
         * note that we don't increment pal_cnt because this is a special not-user-supplied item */
        pal_handles[pal_cnt] = epoll->event.event;
        pal_events[pal_cnt]  = PAL_WAIT_READ;
        ret_events[pal_cnt]  = 0;

        epoll->waiter_cnt++;  /* mark epoll as being waited on (so epoll-update signal is sent) */
        unlock(&epoll_hdl->lock);

        /* TODO: Timeout must be updated in case of retries; otherwise, we may wait for too long */
        PAL_BOL polled = DkStreamsWaitEvents(pal_cnt + 1, pal_handles, pal_events, ret_events, timeout_ms * 1000);

        lock(&epoll_hdl->lock);
        epoll->waiter_cnt--;

        /* update user-supplied epoll items' revents with ret_events of polled PAL handles */
        if (!ret_events[pal_cnt] && polled) {
            /* only if epoll was not updated concurrently and something was actually polled */
            for (int i = 0; i < pal_cnt; i++) {
                LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                    if (!epoll_item->handle || !epoll_item->handle->pal_handle)
                        continue;
                    if (epoll_item->handle->pal_handle != pal_handles[i])
                        continue;

                    if (ret_events[i] & PAL_WAIT_ERROR) {
                        epoll_item->revents  |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;
                        epoll_item->connected = false;
                        /* handle disconnected, must remove it from epoll list */
                        need_update = true;
                    }
                    if (ret_events[i] & PAL_WAIT_READ)
                        epoll_item->revents |= EPOLLIN | EPOLLRDNORM;
                    if (ret_events[i] & PAL_WAIT_WRITE)
                        epoll_item->revents |= EPOLLOUT | EPOLLWRNORM;
                    break;
                }
            }
        }

        PAL_FLG event_handle_update = ret_events[pal_cnt];
        free(pal_handles);
        free(pal_events);

        if (event_handle_update) {
            /* retry if epoll was updated concurrently (similar to Linux semantics) */
            unlock(&epoll_hdl->lock);
            wait_event(&epoll->event);
            lock(&epoll_hdl->lock);
        } else {
            /* no need to retry, exit the while loop */
            break;
        }
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
