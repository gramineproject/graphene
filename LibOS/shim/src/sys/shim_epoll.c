/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "epoll_create", "epoll_create1", "epoll_ctl" and "epoll_wait".
 */

#include <errno.h>
#include <linux/eventpoll.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_table.h"
#include "shim_thread.h"

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

struct shim_fs epoll_builtin_fs;

long shim_do_epoll_create1(int flags) {
    if ((flags & ~EPOLL_CLOEXEC))
        return -EINVAL;

    struct shim_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    hdl->type = TYPE_EPOLL;
    hdl->fs = &epoll_builtin_fs;

    struct shim_epoll_handle* epoll = &hdl->info.epoll;
    epoll->fds_count = 0;
    __atomic_store_n(&epoll->waiter_cnt, 0, __ATOMIC_RELAXED);
    INIT_LISTP(&epoll->fds);

    int ret = create_event(&epoll->event);
    if (ret < 0) {
        put_handle(hdl);
        return ret;
    }

    int vfd = set_new_fd_handle(hdl, (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0, NULL);
    put_handle(hdl);
    return vfd;
}

/* the 'size' argument of epoll_create is not used */
long shim_do_epoll_create(int size) {
    if (size <= 0)
        return -EINVAL;

    return shim_do_epoll_create1(0);
}

static void notify_epoll_waiters(struct shim_epoll_handle* epoll) {
    /* if other threads are currently waiting on epoll_wait(), send a signal to update their
     * epoll items (note that we send waiter_cnt number of signals -- to each waiting thread)
     * XXX(borys): I don't think this is correct: set_event semantics seem to be producers-consumers
     * and here we need to wake all waiting threads. Waiting for this event is done in a loop
     * (`shim_do_epoll_wait`), what if one threads consumes multiple events? */
    size_t waiters = __atomic_load_n(&epoll->waiter_cnt, __ATOMIC_RELAXED);
    if (waiters) {
        /* TODO: this needs error checking. */
        set_event(&epoll->event, waiters);
    }
}

void _update_epolls(struct shim_handle* handle) {
    assert(locked(&handle->lock));

    struct shim_epoll_item* epoll_item;
    LISTP_FOR_EACH_ENTRY(epoll_item, &handle->epolls, back) {
        notify_epoll_waiters(&epoll_item->epoll->info.epoll);
    }
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
         * epoll's `fds` list */
        struct shim_handle* hdl = epoll_item->epoll;
        assert(hdl->type == TYPE_EPOLL);
        struct shim_epoll_handle* epoll = &hdl->info.epoll;

        lock(&hdl->lock);
        LISTP_DEL(epoll_item, &epoll->fds, list);
        epoll->fds_count--;
        notify_epoll_waiters(epoll);
        unlock(&hdl->lock);

        assert(epoll_item->handle == handle);

        free(epoll_item);
    }
}

void maybe_epoll_et_trigger(struct shim_handle* handle, int ret, bool in, bool was_partial) {
    if (ret == -EAGAIN || ret == -EWOULDBLOCK || was_partial) {
        if (in) {
            __atomic_store_n(&handle->needs_et_poll_in, true, __ATOMIC_RELEASE);
        } else {
            __atomic_store_n(&handle->needs_et_poll_out, true, __ATOMIC_RELEASE);
        }
        lock(&handle->lock);
        _update_epolls(handle);
        unlock(&handle->lock);
    }
}

long shim_do_epoll_ctl(int epfd, int op, int fd, struct __kernel_epoll_event* event) {
    struct shim_thread* cur = get_cur_thread();
    int ret = 0;

    if (epfd == fd)
        return -EINVAL;

    if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD)
        if (!is_user_memory_readable(event, sizeof(*event))) {
            return -EFAULT;
        }

    struct shim_handle* epoll_hdl = get_fd_handle(epfd, NULL, cur->handle_map);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    assert(epoll_hdl->type == TYPE_EPOLL);
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
            if (epoll->fds_count == MAX_EPOLL_HANDLES) {
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

            log_debug("add fd %d (handle %p) to epoll handle %p", fd, hdl, epoll);
            epoll_item->fd        = fd;
            epoll_item->events    = event->events;
            epoll_item->data      = event->data;
            epoll_item->revents   = 0;
            epoll_item->handle    = hdl;
            epoll_item->epoll     = epoll_hdl;

            if (epoll_item->events & EPOLLET) {
                __atomic_store_n(&hdl->needs_et_poll_in, true, __ATOMIC_RELEASE);
                __atomic_store_n(&hdl->needs_et_poll_out, true, __ATOMIC_RELEASE);
            }

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
            epoll->fds_count++;
            notify_epoll_waiters(epoll);

            put_handle(hdl);
            break;
        }

        case EPOLL_CTL_MOD: {
            LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                if (epoll_item->fd == fd) {
                    epoll_item->events = event->events;
                    epoll_item->data   = event->data;

                    if (epoll_item->events & EPOLLET) {
                        struct shim_handle* handle = epoll_item->handle;
                        __atomic_store_n(&handle->needs_et_poll_in, true, __ATOMIC_RELEASE);
                        __atomic_store_n(&handle->needs_et_poll_out, true, __ATOMIC_RELEASE);
                    }

                    log_debug("modified fd %d at epoll handle %p", fd, epoll);
                    notify_epoll_waiters(epoll);
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
                    log_debug("delete fd %d (handle %p) from epoll handle %p", fd, hdl, epoll);

                    /* unregister hdl (corresponding to FD) in epoll (corresponding to EPFD):
                     * - unbind hdl from epoll-item via the `back` list
                     * - unbind epoll-item from epoll via the `list` list */
                    lock(&hdl->lock);
                    LISTP_DEL(epoll_item, &hdl->epolls, back);
                    unlock(&hdl->lock);

                    /* note that we already grabbed epoll_hdl->lock so we can safely update epoll */
                    LISTP_DEL(epoll_item, &epoll->fds, list);
                    epoll->fds_count--;
                    notify_epoll_waiters(epoll);

                    free(epoll_item);
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

long shim_do_epoll_wait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                        int timeout_ms) {
    if (maxevents <= 0)
        return -EINVAL;

    if (!is_user_memory_writable(events, sizeof(*events) * maxevents))
        return -EFAULT;

    struct shim_handle* epoll_hdl = get_fd_handle(epfd, NULL, NULL);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    assert(epoll_hdl->type == TYPE_EPOLL);
    struct shim_epoll_handle* epoll = &epoll_hdl->info.epoll;

    lock(&epoll_hdl->lock);

    /* loop to retry on interrupted epoll waits (due to epoll being concurrently updated) */
    while (1) {
        /* wait on epoll's PAL handles + one "event" handle that signals epoll updates */
        PAL_HANDLE* pal_handles = malloc((epoll->fds_count + 1) * sizeof(PAL_HANDLE));
        if (!pal_handles) {
            unlock(&epoll_hdl->lock);
            put_handle(epoll_hdl);
            return -ENOMEM;
        }

        /* allocate one memory region to hold two PAL_FLG arrays: events and revents */
        PAL_FLG* pal_events = malloc((epoll->fds_count + 1) * sizeof(PAL_FLG) * 2);
        if (!pal_events) {
            free(pal_handles);
            unlock(&epoll_hdl->lock);
            put_handle(epoll_hdl);
            return -ENOMEM;
        }
        PAL_FLG* ret_events = pal_events + (epoll->fds_count + 1);

        /* populate pal_events with read/write events from user-supplied epoll items */
        size_t pal_cnt = 0;
        struct shim_epoll_item* epoll_item;
        LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
            assert(epoll_item->handle != NULL);
            if (!epoll_item->handle->pal_handle)
                continue;

            pal_handles[pal_cnt] = epoll_item->handle->pal_handle;
            pal_events[pal_cnt] = (epoll_item->events & (EPOLLIN | EPOLLRDNORM))
                                  ? PAL_WAIT_READ
                                  : 0;
            pal_events[pal_cnt] |= (epoll_item->events & (EPOLLOUT | EPOLLWRNORM))
                                   ? PAL_WAIT_WRITE
                                   : 0;
            ret_events[pal_cnt] = 0;

            if (epoll_item->events & EPOLLET) {
                if (!__atomic_load_n(&epoll_item->handle->needs_et_poll_in, __ATOMIC_ACQUIRE)) {
                    pal_events[pal_cnt] &= ~PAL_WAIT_READ;
                }
                if (!__atomic_load_n(&epoll_item->handle->needs_et_poll_out, __ATOMIC_ACQUIRE)) {
                    pal_events[pal_cnt] &= ~PAL_WAIT_WRITE;
                }
            }

            pal_cnt++;
        }

        assert(pal_cnt <= epoll->fds_count);

        /* populate "event" handle so it waits on read (meaning epoll-update signal arrived);
         * note that we don't increment pal_cnt because this is a special not-user-supplied item */
        pal_handles[pal_cnt] = epoll->event.event;
        pal_events[pal_cnt]  = PAL_WAIT_READ;
        ret_events[pal_cnt]  = 0;

        /* mark epoll as being waited on (so epoll-update signal is sent) */
        __atomic_add_fetch(&epoll->waiter_cnt, 1, __ATOMIC_RELAXED);
        unlock(&epoll_hdl->lock);

        /* TODO: Timeout must be updated in case of retries; otherwise, we may wait for too long */
        long error = DkStreamsWaitEvents(pal_cnt + 1, pal_handles, pal_events, ret_events,
                                         timeout_ms * 1000);
        bool polled = error == 0;
        error = pal_to_unix_errno(error);

        lock(&epoll_hdl->lock);
        __atomic_sub_fetch(&epoll->waiter_cnt, 1, __ATOMIC_RELAXED);

        /* update user-supplied epoll items' revents with ret_events of polled PAL handles */
        if (!ret_events[pal_cnt] && polled) {
            /* only if epoll was not updated concurrently and something was actually polled */
            /* TODO: This loop is wrong. If there are 2 epoll_items with the same pal_handle (e.g.
             * due to dup-ed fd), only the first will be updated.
             * GH issue: https://github.com/oscarlab/graphene/issues/1848 */
            for (size_t i = 0; i < pal_cnt; i++) {
                LISTP_FOR_EACH_ENTRY(epoll_item, &epoll->fds, list) {
                    assert(epoll_item->handle != NULL);
                    if (!epoll_item->handle->pal_handle)
                        continue;
                    if (epoll_item->handle->pal_handle != pal_handles[i])
                        continue;

                    if (ret_events[i] & PAL_WAIT_ERROR) {
                        epoll_item->revents  |= EPOLLERR | EPOLLHUP | EPOLLRDHUP;
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

        if (error && error != -EAGAIN) {
            unlock(&epoll_hdl->lock);
            put_handle(epoll_hdl);
            if (error == -EINTR) {
                /* `epoll_wait` and `epoll_pwait` are not restarted after being interrupted by
                 * a signal handler. */
                error = -ERESTARTNOHAND;
            }
            return error;
        } else if (event_handle_update) {
            /* retry if epoll was updated concurrently (similar to Linux semantics) */
            unlock(&epoll_hdl->lock);
            int ret = wait_event(&epoll->event);
            if (ret < 0) {
                put_handle(epoll_hdl);
                return ret;
            }
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
            if (events[nevents].events & (EPOLLIN | EPOLLRDNORM)) {
                __atomic_store_n(&epoll_item->handle->needs_et_poll_in, false, __ATOMIC_RELEASE);
            }
            if (events[nevents].events & (EPOLLOUT | EPOLLWRNORM)) {
                __atomic_store_n(&epoll_item->handle->needs_et_poll_out, false, __ATOMIC_RELEASE);
            }
            epoll_item->revents &= ~epoll_item->events; /* informed user about revents, may clear */
            nevents++;
        }
    }

    unlock(&epoll_hdl->lock);
    put_handle(epoll_hdl);
    return nevents;
}

long shim_do_epoll_pwait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                         int timeout_ms, const __sigset_t* sigmask, size_t sigsetsize) {
    __UNUSED(sigmask);
    __UNUSED(sigsetsize);
    int ret = shim_do_epoll_wait(epfd, events, maxevents, timeout_ms);
    return ret;
}

static int epoll_close(struct shim_handle* epoll_hdl) {
    assert(epoll_hdl->type == TYPE_EPOLL);
    struct shim_epoll_handle* epoll = &epoll_hdl->info.epoll;
    struct shim_epoll_item* epoll_item;
    struct shim_epoll_item* tmp_epoll_item;

    lock(&epoll_hdl->lock);

    LISTP_FOR_EACH_ENTRY_SAFE(epoll_item, tmp_epoll_item, &epoll->fds, list) {
        struct shim_handle* hdl = epoll_item->handle;

        lock(&hdl->lock);
        LISTP_DEL(epoll_item, &hdl->epolls, back);
        unlock(&hdl->lock);

        LISTP_DEL(epoll_item, &epoll->fds, list);
        epoll->fds_count--;
        free(epoll_item);
    }

    unlock(&epoll_hdl->lock);

    destroy_event(&epoll->event);

    return 0;
}

struct shim_fs_ops epoll_fs_ops = {
    .close = &epoll_close,
};

struct shim_fs epoll_builtin_fs = {
    .name   = "epoll",
    .fs_ops = &epoll_fs_ops,
};

BEGIN_CP_FUNC(epoll_item) {
    __UNUSED(size);
    assert(size == sizeof(LISTP_TYPE(shim_epoll_item)));

    LISTP_TYPE(shim_epoll_item)* old_list = (LISTP_TYPE(shim_epoll_item)*)obj;
    LISTP_TYPE(shim_epoll_item)* new_list = (LISTP_TYPE(shim_epoll_item)*)objp;
    struct shim_epoll_item* epoll_item;

    log_debug("checkpoint epoll: %p -> %p (base = 0x%08lx)", old_list, new_list, base);

    INIT_LISTP(new_list);

    LISTP_FOR_EACH_ENTRY(epoll_item, old_list, list) {
        size_t off = ADD_CP_OFFSET(sizeof(struct shim_epoll_item));

        struct shim_epoll_item* new_epoll_item = (struct shim_epoll_item*)(base + off);

        new_epoll_item->fd        = epoll_item->fd;
        new_epoll_item->events    = epoll_item->events;
        new_epoll_item->data      = epoll_item->data;
        new_epoll_item->revents   = epoll_item->revents;
        new_epoll_item->epoll     = NULL; // To be filled by epoll handle RS_FUNC

        LISTP_ADD(new_epoll_item, new_list, list);

        DO_CP(handle, epoll_item->handle, &new_epoll_item->handle);

        LISTP_ADD(new_epoll_item, &new_epoll_item->handle->epolls, back);
    }

    ADD_CP_FUNC_ENTRY((uintptr_t)objp - base);
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
    }
}
END_RS_FUNC(epoll_item)
