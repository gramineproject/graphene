/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/eventpoll.h>

/* Avoid duplicated definitions */
#ifndef EPOLLIN

#define EPOLLIN         0x001
#define EPOLLPRI        0x002
#define EPOLLOUT        0x004
#define EPOLLRDNORM     0x040
#define EPOLLRDBAND     0x080
#define EPOLLWRNORM     0x100
#define EPOLLERBAND     0x200
#define EPOLLERR        0x008
#define EPOLLHUP        0x010
#define EPOLLRDHUP      0x2000

#endif


#define MAX_EPOLL_FDS       1024

struct shim_mount epoll_builtin_fs;

/* shim_epoll_fds are linked as a list (by the list field), 
 * hanging off of a shim_epoll_handle (by the fds field) */
struct shim_epoll_fd {
    FDTYPE                      fd;
    unsigned int                events;
    __u64                       data;
    unsigned int                revents;
    struct shim_handle *        handle;
    struct shim_handle *        epoll;
    PAL_HANDLE                  pal_handle;
    LIST_TYPE(shim_epoll_fd)    list;
    LIST_TYPE(shim_epoll_fd)    back;
};

int shim_do_epoll_create1 (int flags)
{
    if ((flags & ~EPOLL_CLOEXEC))
        return -EINVAL;

    struct shim_handle * hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    struct shim_epoll_handle * epoll = &hdl->info.epoll;

    hdl->type = TYPE_EPOLL;
    set_handle_fs(hdl, &epoll_builtin_fs);
    epoll->maxfds = MAX_EPOLL_FDS;
    epoll->nfds = 0;
    epoll->pal_fds = malloc(sizeof(FDTYPE) * MAX_EPOLL_FDS);
    epoll->pal_handles = malloc(sizeof(PAL_HANDLE) * MAX_EPOLL_FDS);
    create_event(&epoll->event);
    INIT_LISTP(&epoll->fds);

    int vfd = set_new_fd_handle(hdl, (flags & EPOLL_CLOEXEC) ? FD_CLOEXEC : 0,
                                NULL);
    put_handle(hdl);
    return vfd;
}

/* the 'size' argument of epoll_create is not used */
int shim_do_epoll_create (int size)
{
    if (size < 0)
        return -EINVAL;

    return shim_do_epoll_create1(0);
}

static void update_epoll (struct shim_epoll_handle * epoll)
{
    struct shim_epoll_fd * tmp;
    int npals = 0;
    epoll->nread = 0;

    listp_for_each_entry(tmp, &epoll->fds, list) {
        if (!tmp->pal_handle)
            continue;

        debug("found handle %p (pal handle %p) from epoll handle %p\n",
              tmp->handle, tmp->pal_handle, epoll);

        epoll->pal_fds[npals] = tmp->fd;
        epoll->pal_handles[npals] = tmp->pal_handle;
        npals++;
        if (tmp->handle->acc_mode & MAY_READ)
            epoll->nread++;
    }

    epoll->npals = npals;

    if (epoll->nwaiters)
        set_event(&epoll->event, epoll->nwaiters);
}

int delete_from_epoll_handles (struct shim_handle * handle)
{
    while (1) {
        lock(handle->lock);

        if (listp_empty(&handle->epolls)) {
            unlock(handle->lock);
            break;
        }

        struct shim_epoll_fd * epoll_fd = listp_first_entry(&handle->epolls,
                                 struct shim_epoll_fd, back);

        listp_del(epoll_fd, &handle->epolls, back);
        unlock(handle->lock);
        put_handle(handle);

        struct shim_handle * epoll_hdl = epoll_fd->epoll;
        struct shim_epoll_handle * epoll = &epoll_hdl->info.epoll;

        debug("delete handle %p from epoll handle %p\n", handle,
              &epoll_hdl->info.epoll);

        lock(epoll_hdl->lock);

        listp_del(epoll_fd, &epoll->fds, list);
        free(epoll_fd);

        epoll_hdl->info.epoll.nfds--;
        update_epoll(&epoll_hdl->info.epoll);
        unlock(epoll_hdl->lock);
        put_handle(epoll_hdl);
    }

    return 0;
}

int shim_do_epoll_ctl (int epfd, int op, int fd,
                       struct __kernel_epoll_event * event)
{
    struct shim_thread * cur = get_cur_thread();
    int ret = 0;

    struct shim_handle * epoll_hdl = get_fd_handle(epfd, NULL, cur->handle_map);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    struct shim_epoll_handle * epoll = &epoll_hdl->info.epoll;
    struct shim_epoll_fd * epoll_fd;

    lock(epoll_hdl->lock);

    switch (op) {
        case EPOLL_CTL_ADD: {
            listp_for_each_entry(epoll_fd, &epoll->fds, list)
                if (epoll_fd->fd == fd) {
                    ret = -EEXIST;
                    goto out;
                }

            struct shim_handle * hdl = get_fd_handle(fd, NULL, cur->handle_map);
            if (!hdl) {
                ret = -EBADF;
                goto out;
            }
            if ((hdl->type != TYPE_PIPE && hdl->type != TYPE_SOCK) ||
                !hdl->pal_handle) {
                ret = -EPERM;
                put_handle(hdl);
                goto out;
            }
            if (epoll->nfds == MAX_EPOLL_FDS) {
                ret = -ENOSPC;
                put_handle(hdl);
                goto out;
            }

            debug("add handle %p to epoll handle %p\n", hdl, epoll);

            epoll_fd = malloc(sizeof(struct shim_epoll_fd));
            epoll_fd->fd = fd;
            epoll_fd->events = event->events;
            epoll_fd->data = event->data;
            epoll_fd->revents = 0;
            epoll_fd->handle = hdl;
            epoll_fd->epoll = epoll_hdl;
            epoll_fd->pal_handle = hdl->pal_handle;

            /* Register the epoll handle */
            get_handle(epoll_hdl);
            lock(hdl->lock);
            INIT_LIST_HEAD(epoll_fd, back);
            listp_add_tail(epoll_fd, &hdl->epolls, back);
            unlock(hdl->lock);

            INIT_LIST_HEAD(epoll_fd, list);
            listp_add_tail(epoll_fd, &epoll->fds, list);
            epoll->nfds++;
            goto update;
        }

        case EPOLL_CTL_MOD: {
            listp_for_each_entry(epoll_fd, &epoll->fds, list)
                if (epoll_fd->fd == fd) {
                    epoll_fd->events = event->events;
                    epoll_fd->data = event->data;
                    goto update;
                }

            ret = -ENOENT;
            goto out;
        }

        case EPOLL_CTL_DEL: {
            listp_for_each_entry(epoll_fd, &epoll->fds, list)
                if (epoll_fd->fd == fd) {
                    struct shim_handle * hdl = epoll_fd->handle;

                    /* Unregister the epoll handle */
                    lock(hdl->lock);
                    listp_del(epoll_fd, &hdl->epolls, back);
                    unlock(hdl->lock);
                    put_handle(epoll_hdl);

                    debug("delete handle %p from epoll handle %p\n",
                          hdl, epoll);

                    listp_del(epoll_fd, &epoll->fds, list);
                    epoll->nfds--;
                    free(epoll_fd);
                    goto update;
                }

            ret = -ENOENT;
            goto out;
        }

        default:
            ret = -ENOSYS;
            goto out;
    }

update:
    update_epoll(epoll);
out:
    unlock(epoll_hdl->lock);
    put_handle(epoll_hdl);
    return ret;
}

int shim_do_epoll_wait (int epfd, struct __kernel_epoll_event * events,
                        int maxevents, int timeout)
{
    int ret = 0;
    struct shim_handle * epoll_hdl = get_fd_handle(epfd, NULL, NULL);
    if (!epoll_hdl)
        return -EBADF;
    if (epoll_hdl->type != TYPE_EPOLL) {
        put_handle(epoll_hdl);
        return -EINVAL;
    }

    struct shim_epoll_handle * epoll = &epoll_hdl->info.epoll;
    struct shim_epoll_fd * epoll_fd;
    int nevents = 0;
    int npals, nread;
    bool need_update = false;

    lock(epoll_hdl->lock);
retry:
    if (!(npals = epoll->npals))
        goto reply;

    if ((nread = epoll->nread))
        epoll->nwaiters++;

    // Allocate space for one additional PAL_HANDLE to accommodate the special
    // events handle. Graphene monitors the special events handle to detect if the
    // epoll handle was modified while waiting for associated events. If the
    // epoll handle was modified concurrently, we re-issue the PAL call. This
    // reflects the expected semantic of being able to modify the epoll handle
    // while it is actively used.
    PAL_HANDLE * pal_handles = __alloca(sizeof(PAL_HANDLE) * (npals + 1));
    PAL_FLG * pal_events = __alloca(sizeof(PAL_FLG) * (npals + 1) * 2);
    PAL_FLG * ret_events = pal_events + (npals + 1);

    npals = 0;
    listp_for_each_entry(epoll_fd, &epoll->fds, list) {
        if (!epoll_fd->pal_handle)
            continue;
        pal_handles[npals] = epoll_fd->pal_handle;
        assert(epoll_fd->pal_handle == epoll->pal_handles[npals]);
        pal_events[npals]  = (epoll_fd->events & EPOLLIN ) ? PAL_WAIT_READ  : 0;
        pal_events[npals] |= (epoll_fd->events & EPOLLOUT) ? PAL_WAIT_WRITE : 0;
        ret_events[npals] = 0;
        debug("%s:%d fd=%d %s|%s\n", __FUNCTION__, __LINE__, epoll_fd->fd,
              (epoll_fd->events & EPOLLIN) ? "EPOLLIN" : "0",
              (epoll_fd->events & EPOLLOUT) ? "EPOLLOUT" : "0");
        npals++;
    }
    pal_handles[npals] = epoll->event.event;
    pal_events[npals] = PAL_WAIT_READ;
    ret_events[npals] = 0;

    unlock(epoll_hdl->lock);
    
    // TODO: Timeout must be updated in case of retries. Otherwise, we may
    // wait too long.
    uint64_t pal_timeout = timeout;
    PAL_BOL polled = DkObjectsWaitEvents(npals, pal_handles, pal_events, ret_events, pal_timeout);
    
    lock(epoll_hdl->lock);

    if (nread)
        epoll->nwaiters--;

    if (!polled)
        goto reply;
    
    for (int i = 0; i < npals; i++) {
        listp_for_each_entry(epoll_fd, &epoll->fds, list) {
            if (!epoll_fd->pal_handle)
                continue;
            if(epoll_fd->pal_handle != pal_handles[i])
                continue;

            if (ret_events[i] & PAL_WAIT_ERROR) {
                epoll_fd->revents |= EPOLLERR|EPOLLHUP|EPOLLRDHUP;
                epoll_fd->pal_handle = NULL;
                need_update = true;
            }
            if (ret_events[i] & PAL_WAIT_READ) {
                epoll_fd->revents |= EPOLLIN;
            }
            if (ret_events[i] & PAL_WAIT_WRITE) {
                epoll_fd->revents |= EPOLLOUT;
            }
            break;
        }
    }

    if (ret_events[npals]) {
        wait_event(&epoll->event);
        goto retry;
    }
    
reply:
    listp_for_each_entry(epoll_fd, &epoll->fds, list) {
        if (nevents == maxevents)
            break;

        if ((epoll_fd->events|EPOLLERR|EPOLLHUP) & epoll_fd->revents) {
            events[nevents].events =
                    (epoll_fd->events|EPOLLERR|EPOLLHUP) & epoll_fd->revents;
            events[nevents].data = epoll_fd->data;
            epoll_fd->revents &= ~epoll_fd->events;
            debug("fd=%d %s|%s|%s\n", epoll_fd->fd,
                  (events[nevents].events & EPOLLIN) ? "EPOLLIN" : "0",
                  (events[nevents].events & EPOLLOUT) ? "EPOLLOUT" : "0",
                  (events[nevents].events & EPOLLERR) ? "EPOLLERR" : "0");
                  
            nevents++;
        }
    }

    if (need_update)
        update_epoll(epoll);

    unlock(epoll_hdl->lock);
    ret = nevents;
    put_handle(epoll_hdl);
    return ret;
}

int shim_do_epoll_pwait (int epfd, struct __kernel_epoll_event * events,
                         int maxevents, int timeout, const __sigset_t * sigmask,
                         size_t sigsetsize)
{
    int ret = shim_do_epoll_wait (epfd, events, maxevents, timeout);
    return ret;
}

static int epoll_close (struct shim_handle * hdl)
{
    return 0;
}

struct shim_fs_ops epoll_fs_ops = {
        .close    = &epoll_close,
    };

struct shim_mount epoll_builtin_fs = { .type = "epoll",
                                       .fs_ops = &epoll_fs_ops, };

BEGIN_CP_FUNC(epoll_fd)
{
    assert(size == sizeof(LISTP_TYPE(shim_epoll_fd)));

    LISTP_TYPE(shim_epoll_fd) * old_list = (LISTP_TYPE(shim_epoll_fd) *) obj;
    LISTP_TYPE(shim_epoll_fd) * new_list = (LISTP_TYPE(shim_epoll_fd) *) objp;
    struct shim_epoll_fd * epoll_fd;

    debug("checkpoint epoll: %p -> %p (base = %p)\n", old_list, new_list, base);

    INIT_LISTP(new_list);

    listp_for_each_entry(epoll_fd, old_list, list) {
        ptr_t off = ADD_CP_OFFSET(sizeof(struct shim_epoll_fd));

        struct shim_epoll_fd * new_epoll_fd =
                    (struct shim_epoll_fd *) (base + off);

        new_epoll_fd->fd      = epoll_fd->fd;
        new_epoll_fd->events  = epoll_fd->events;
        new_epoll_fd->data    = epoll_fd->data;
        new_epoll_fd->revents = epoll_fd->revents;
        new_epoll_fd->pal_handle = NULL;

        listp_add(new_epoll_fd, new_list, list);

        DO_CP(handle, epoll_fd->handle, &new_epoll_fd->handle);
    }

    ADD_CP_FUNC_ENTRY((ptr_t) objp - base);
}
END_CP_FUNC(epoll_fd)

BEGIN_RS_FUNC(epoll_fd)
{
    LISTP_TYPE(shim_epoll_fd) * list = (void *) (base + GET_CP_FUNC_ENTRY());
    struct shim_epoll_fd * epoll_fd;

    CP_REBASE(*list);

    listp_for_each_entry(epoll_fd, list, list) {

        CP_REBASE(epoll_fd->handle);
        CP_REBASE(epoll_fd->back);
        epoll_fd->pal_handle = epoll_fd->handle->pal_handle;
        CP_REBASE(epoll_fd->list);

        DEBUG_RS("fd=%d,path=%s,type=%s,uri=%s",
                 epoll_fd->fd, qstrgetstr(&epoll_fd->handle->path),
                 epoll_fd->handle->fs_type,
                 qstrgetstr(&epoll_fd->handle->uri));
    }
}
END_RS_FUNC(epoll_fd)
