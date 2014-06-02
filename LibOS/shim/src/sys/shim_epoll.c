/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
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

#include <pal.h>
#include <pal_error.h>

#include <errno.h>
#include <sys/epoll.h>
#include <sys/poll.h>

#define MAX_EPOLL_FDS       1024

struct shim_mount epoll_builtin_fs;

struct shim_epoll_fd {
    FDTYPE                      fd;
    unsigned int                events;
    __u64                       data;
    unsigned int                revents;
    struct shim_handle *        handle;
    PAL_HANDLE                  pal_handle;
    struct list_head            list;
};

int shim_do_epoll_create1 (int flags)
{
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
    INIT_LIST_HEAD(&epoll->fds);

    int vfd = set_new_fd_handle(hdl, flags, NULL);
    put_handle(hdl);
    return vfd;
}

/* the 'size' argument of epoll_create is not used */
int shim_do_epoll_create (int size)
{
    return shim_do_epoll_create1(0);
}

static void update_epoll (struct shim_epoll_handle * epoll)
{
    struct shim_epoll_fd * tmp;
    int npals = 0;
    epoll->nread = 0;

    list_for_each_entry(tmp, &epoll->fds, list) {
        if (!tmp->pal_handle)
            continue;
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
            list_for_each_entry(epoll_fd, &epoll->fds, list)
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

            epoll_fd = malloc(sizeof(struct shim_epoll_fd));
            epoll_fd->fd = fd;
            epoll_fd->events = event->events;
            epoll_fd->data = event->data;
            epoll_fd->revents = 0;
            epoll_fd->handle = hdl;
            epoll_fd->pal_handle = hdl->pal_handle;

            INIT_LIST_HEAD(&epoll_fd->list);
            list_add_tail(&epoll_fd->list, &epoll->fds);
            epoll->nfds++;
            goto update;
        }

        case EPOLL_CTL_MOD: {
            list_for_each_entry(epoll_fd, &epoll->fds, list)
                if (epoll_fd->fd == fd) {
                    epoll_fd->events = event->events;
                    epoll_fd->data = event->data;
                    goto update;
                }

            ret = -ENOENT;
            goto out;
        }

        case EPOLL_CTL_DEL: {
            list_for_each_entry(epoll_fd, &epoll->fds, list)
                if (epoll_fd->fd == fd) {
                    list_del(&epoll_fd->list);
                    put_handle(epoll_fd->handle);
                    free(epoll_fd);
                    epoll->nfds--;
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

    PAL_HANDLE * pal_handles = __alloca(sizeof(PAL_HANDLE) * (npals + 1));
    FDTYPE * fds = __alloca(sizeof(FDTYPE) * npals);
    memcpy(fds, epoll->pal_fds, sizeof(FDTYPE) * npals);
    memcpy(pal_handles, epoll->pal_handles, sizeof(PAL_HANDLE) * npals);
    pal_handles[npals] = epoll->event.event;

    if ((nread = epoll->nread))
        epoll->nwaiters++;

    unlock(epoll_hdl->lock);

    PAL_HANDLE polled = DkObjectsWaitAny(nread ? npals + 1 : npals, pal_handles,
                                         nread ? NO_TIMEOUT : 0);

    lock(epoll_hdl->lock);

    if (nread)
        epoll->nwaiters--;

    if (!polled)
        goto reply;

    if (polled == epoll->event.event) {
        wait_event(&epoll->event);
        goto retry;
    }

    PAL_STREAM_ATTR attr;
    if (!DkStreamAttributesQuerybyHandle(polled, &attr))
        goto reply;

    list_for_each_entry(epoll_fd, &epoll->fds, list)
        if (polled == epoll_fd->pal_handle) {
            debug("epoll: fd %d polled\n", epoll_fd->fd);
            if (attr.disconnected) {
                epoll_fd->revents |= EPOLLERR|EPOLLHUP|EPOLLRDHUP;
                epoll_fd->pal_handle = NULL;
                need_update = true;
            }
            if (attr.readable)
                epoll_fd->revents |= EPOLLIN;
            if (attr.writeable)
                epoll_fd->revents |= EPOLLOUT;
            break;
        }

reply:
    list_for_each_entry(epoll_fd, &epoll->fds, list) {
        if (nevents == maxevents)
            break;

        if ((epoll_fd->events|EPOLLERR|EPOLLHUP) & epoll_fd->revents) {
            events[nevents].events =
                    (epoll_fd->events|EPOLLERR|EPOLLHUP) & epoll_fd->revents;
            events[nevents].data = epoll_fd->data;
            nevents++;
            epoll_fd->revents &= ~epoll_fd->events;
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
                         int maxevents, int timeout, const sigset_t * sigmask,
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
