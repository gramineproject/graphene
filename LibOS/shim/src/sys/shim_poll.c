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
 * shim_poll.c
 *
 * Implementation of system call "poll", "ppoll", "select" and "pselect6".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>
#include <list.h>

#include <errno.h>

#include <linux/fcntl.h>

noreturn void
fortify_fail (const char *msg)
{
    /* The loop is added only to keep gcc happy.  */
    while (1)
        debug("*** %s ***\n", msg);
}

noreturn void
chk_fail (void)
{
    fortify_fail ("buffer overflow detected");
}

static inline __attribute__((always_inline))
void * __try_alloca (struct shim_thread * cur, int size)
{
    if (!size)
        return NULL;

    if (check_stack_size(cur, size))
        return __alloca(size);
    else
        return malloc(size);
}

static inline __attribute__((always_inline))
void __try_free (struct shim_thread * cur, void * mem)
{
    if (mem && !check_on_stack(cur, mem))
        free(mem);
}

DEFINE_PROFILE_CATEGORY(__do_poll, select);
DEFINE_PROFILE_INTERVAL(do_poll_get_handle, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_search_repeat, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_set_bookkeeping, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_check_accmode, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_vfs_polling, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_update_bookkeeping, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_first_loop, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_second_loop, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_wait_any, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_wait_any_peek, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_third_loop, __do_poll);
DEFINE_PROFILE_INTERVAL(do_poll_fourth_loop, __do_poll);

#define DO_R            0001
#define DO_W            0002
#define KNOWN_R         0004
#define KNOWN_W         0010
#define RET_R           0020
#define RET_W           0040
#define RET_E           0100
#define POLL_R          0200
#define POLL_W          0400

struct poll_handle {
    unsigned short       flags;
    FDTYPE               fd;
    struct shim_handle * handle;
    struct poll_handle * next;
    struct poll_handle * children;
} __attribute__((packed));

#define POLL_NOTIMEOUT  ((uint64_t)-1)

static int __do_poll(int npolls, struct poll_handle* polls, uint64_t timeout_us) {
    struct shim_thread* cur = get_cur_thread();
    struct shim_handle_map* map = cur->handle_map;
    int npals = 0;
    struct poll_handle* polling = NULL;
    struct poll_handle* p;
    struct poll_handle* q;
    struct poll_handle** n;
    PAL_HANDLE* pals = NULL;
    PAL_FLG* pal_events = NULL;
    PAL_FLG* ret_events = NULL;
    int ret = 0;

#ifdef PROFILE
    unsigned long begin_time = GET_PROFILE_INTERVAL();
    BEGIN_PROFILE_INTERVAL_SET(begin_time);
#endif

    lock(&map->lock);

    for (p = polls ; p < polls + npolls ; p++) {
        bool do_r = p->flags & DO_R;
        bool do_w = p->flags & DO_W;

        if (!do_r && !do_w) {
no_op:
            p->flags  = 0;
            p->handle = NULL;
            UPDATE_PROFILE_INTERVAL();
            continue;
        }

        struct shim_handle * hdl = __get_fd_handle(p->fd, NULL, map);
        if (!hdl->fs || !hdl->fs->fs_ops)
            goto no_op;

        SAVE_PROFILE_INTERVAL(do_poll_get_handle);

        /* search for a repeated entry */
        struct poll_handle * rep = polling;
        for ( ; rep ; rep = rep->next)
            if (rep->handle == hdl)
                break;

        SAVE_PROFILE_INTERVAL(do_poll_search_repeat);

        p->flags    = (do_r ? DO_R : 0)|(do_w ? DO_W : 0);
        p->handle   = NULL;
        p->next     = NULL;
        p->children = NULL;

        if (rep) {
            /* if there is repeated handles and we already know the
               result, let's skip them */
            if (rep->flags & (KNOWN_R|POLL_R)) {
                p->flags = rep->flags & (KNOWN_R|RET_R|RET_E|POLL_R);
                do_r = false;
            }

            if (rep->flags & (KNOWN_W|POLL_W)) {
                p->flags = rep->flags & (KNOWN_W|RET_W|RET_E|POLL_W);
                do_w = false;
            }

            p->next = rep->children;
            rep->children = p;

            if (!do_r && !do_w) {
                SAVE_PROFILE_INTERVAL(do_poll_set_bookkeeping);
                continue;
            }
        } else {
            get_handle(hdl);
            p->handle = hdl;
            p->next = polling;
            polling = p;
        }

        SAVE_PROFILE_INTERVAL(do_poll_set_bookkeeping);

        /* do the easiest check, check handle's access mode */
        if (do_r && !(hdl->acc_mode & MAY_READ)) {
            p->flags |= KNOWN_R;
            debug("fd %d known to be not readable\n", p->fd);
            do_r = false;
        }

        if (do_w && !(hdl->acc_mode & MAY_WRITE)) {
            p->flags |= KNOWN_W;
            debug("fd %d known to be not writable\n", p->fd);
            do_w = false;
        }

        SAVE_PROFILE_INTERVAL(do_poll_check_accmode);

        if (!do_r && !do_w)
            goto done_finding;

        /* if fs provides a poll operator, let's try it. */
        if (hdl->fs->fs_ops->poll) {
            int need_poll = 0;

            if (do_r && !(p->flags & POLL_R))
                need_poll |= FS_POLL_RD;
            if (do_w && !(p->flags & POLL_W))
                need_poll |= FS_POLL_WR;

            if (need_poll) {
                int polled = hdl->fs->fs_ops->poll(hdl, need_poll);

                if (polled < 0) {
                    if (polled != -EAGAIN) {
                        unlock(&map->lock);
                        ret = polled;
                        goto done_polling;
                    }
                } else {
                    if (polled & FS_POLL_ER) {
                        debug("fd %d known to have error\n", p->fd);
                        p->flags |= KNOWN_R|KNOWN_W|RET_E;
                        do_r = do_w = false;
                    }

                    if ((polled & FS_POLL_RD)) {
                        debug("fd %d known to be readable\n", p->fd);
                        p->flags |= KNOWN_R|RET_R;
                        do_r = false;
                    }

                    if (polled & FS_POLL_WR) {
                        debug("fd %d known to be writable\n", p->fd);
                        p->flags |= KNOWN_W|RET_W;
                        do_w = false;
                    }
                }
            }

            SAVE_PROFILE_INTERVAL(do_poll_vfs_polling);

            if (!do_r && !do_w)
                goto done_finding;
        }

        struct poll_handle * to_poll = rep ? : p;

        if (!(to_poll->flags & (POLL_R|POLL_W))) {
            if (!hdl->pal_handle) {
                p->flags |= KNOWN_R|KNOWN_W|RET_E;
                do_r = do_w = false;
                goto done_finding;
            }

            debug("polling fd %d\n", to_poll->fd);
            npals++;
        }

        to_poll->flags |= (do_r ? POLL_R : 0)|(do_w ? POLL_W : 0);

done_finding:
        /* feedback the new knowledge of repeated handles */
        if (rep)
            rep->flags |= p->flags & (KNOWN_R|KNOWN_W|RET_R|RET_W|RET_E|POLL_R|POLL_W);

        SAVE_PROFILE_INTERVAL(do_poll_update_bookkeeping);
    }

    unlock(&map->lock);

    SAVE_PROFILE_INTERVAL_SINCE(do_poll_first_loop, begin_time);

    if (!npals) {
        ret = 0;
        goto done_polling;
    }

    /* Try to allocate the arguments for DkObjectsWaitEvents() on stack, or use malloc() */
    pals = __try_alloca(cur, sizeof(PAL_HANDLE) * npals);
    pal_events = __try_alloca(cur, sizeof(PAL_FLG) * npals);
    ret_events = __try_alloca(cur, sizeof(PAL_FLG) * npals);
    npals = 0;

    if (!pals || !pal_events || !ret_events) {
        ret = -ENOMEM;
        goto done_polling;
    }

    n = &polling;
    for (p = polling ; p ; p = p->next) {
        assert(p->handle);

        if (!(p->flags & (POLL_R|POLL_W))) {
            *n = p->next;
            put_handle(p->handle);
            p->handle = NULL;
            continue;
        }

        pals[npals] = p->handle->pal_handle;
        pal_events[npals] = ((p->flags & POLL_R) ? PAL_WAIT_READ  : 0) |
                            ((p->flags & POLL_W) ? PAL_WAIT_WRITE : 0);
        ret_events[npals] = 0;
        npals++;
        n = &p->next;
    }

    SAVE_PROFILE_INTERVAL(do_poll_second_loop);

    PAL_BOL polled = DkObjectsWaitEvents(npals, pals, pal_events, ret_events, timeout_us);

    SAVE_PROFILE_INTERVAL(do_poll_wait);

    if (!polled) {
        ret = (PAL_NATIVE_ERRNO == PAL_ERROR_TRYAGAIN) ? 0 : -PAL_ERRNO;
        goto done_polling;
    }

    p = polling;
    for (int i = 0 ; p ; i++, p = p->next) {
        assert(p->handle->pal_handle == pals[i]);

        if (!ret_events[i])
            continue;

        debug("handle %s is polled\n", qstrgetstr(&p->handle->uri));

        p->flags |= KNOWN_R|KNOWN_W;

        if (ret_events[i] & PAL_WAIT_ERROR) {
            debug("handle is polled to be disconnected\n");
            p->flags |= RET_E;
        }

        if (ret_events[i] & PAL_WAIT_READ) {
            debug("handle is polled to be readable\n");
            p->flags |= RET_R;
        }

        if (ret_events[i] & PAL_WAIT_WRITE) {
            debug("handle is polled to be writeable\n");
            p->flags |= RET_W;
        }

        for (q = p->children ; q ; q = q->next)
            q->flags |= p->flags & (KNOWN_R|KNOWN_W|RET_W|RET_R|RET_E);

        SAVE_PROFILE_INTERVAL(do_poll_third_loop);
    }

    ret = 0;
done_polling:
    for (p = polling ; p ; p = p->next)
        put_handle(p->handle);

    SAVE_PROFILE_INTERVAL(do_poll_fourth_loop);

    /* Free the arguments if they are allocated from malloc() */
    if (pals)
        __try_free(cur, pals);
    if (pal_events)
        __try_free(cur, pal_events);
    if (ret_events)
        __try_free(cur, ret_events);

    return ret;
}

int shim_do_poll (struct pollfd * fds, nfds_t nfds, int timeout_ms)
{
    struct shim_thread * cur = get_cur_thread();

    struct poll_handle * polls =
            __try_alloca(cur, sizeof(struct poll_handle) * nfds);

    for (size_t i = 0 ; i < nfds ; i++) {
        polls[i].fd = fds[i].fd;
        polls[i].flags = 0;
        if (fds[i].events & (POLLIN|POLLRDNORM))
            polls[i].flags |= DO_R;
        if (fds[i].events & (POLLOUT|POLLWRNORM))
            polls[i].flags |= DO_W;
    }

    int ret = __do_poll(nfds, polls,
                        timeout_ms < 0 ? POLL_NOTIMEOUT : timeout_ms * 1000ULL);

    if (ret < 0)
        goto out;

    ret = 0;

    for (size_t i = 0 ; i < nfds ; i++) {
        fds[i].revents = 0;

        if (polls[i].flags & RET_R)
            fds[i].revents |= (fds[i].events & (POLLIN|POLLRDNORM));
        if (polls[i].flags & RET_W)
            fds[i].revents |= (fds[i].events & (POLLOUT|POLLWRNORM));
        if (polls[i].flags & RET_E)
            fds[i].revents |= (POLLERR|POLLHUP);

        if (fds[i].revents)
            ret++;
    }

out:
    __try_free(cur, polls);

    return ret;
}

int shim_do_ppoll (struct pollfd * fds, int nfds, struct timespec * tsp,
                   const __sigset_t * sigmask, size_t sigsetsize)
{
    __UNUSED(sigmask);
    __UNUSED(sigsetsize);
    struct shim_thread * cur = get_cur_thread();

    struct poll_handle * polls =
            __try_alloca(cur, sizeof(struct poll_handle) * nfds);

    for (int i = 0 ; i < nfds ; i++) {
        polls[i].fd = fds[i].fd;
        polls[i].flags = 0;
        if (fds[i].events & (POLLIN|POLLRDNORM))
            polls[i].flags |= DO_R;
        if (fds[i].events & (POLLOUT|POLLWRNORM))
            polls[i].flags |= DO_W;
    }

    uint64_t timeout_us = tsp ? tsp->tv_sec * 1000000ULL + tsp->tv_nsec / 1000 : POLL_NOTIMEOUT;
    int ret = __do_poll(nfds, polls, timeout_us);

    if (ret < 0)
        goto out;

    ret = 0;

    for (int i = 0 ; i < nfds ; i++) {
        fds[i].revents = 0;

        if (polls[i].flags & RET_R)
            fds[i].revents |= (fds[i].events & (POLLIN|POLLRDNORM));
        if (polls[i].flags & RET_W)
            fds[i].revents |= (fds[i].events & (POLLOUT|POLLWRNORM));
        if (polls[i].flags & RET_E)
            fds[i].revents |= (fds[i].events & (POLLERR|POLLHUP));

        if (fds[i].revents)
            ret++;
    }

out:
    __try_free(cur, polls);

    return ret;
}

typedef long int __fd_mask;

#ifndef __NFDBITS
#define __NFDBITS    (8 * (int)sizeof(__fd_mask))
#endif
#ifndef __FDS_BITS
#define __FDS_BITS(set) ((set)->fds_bits)
#endif

/* We don't use `memset' because this would require a prototype and
   the array isn't too big.  */
# define __FD_ZERO(set)                                     \
    do {                                                    \
        unsigned int __i;                                   \
        fd_set *__arr = (set);                              \
        for (__i = 0; __i < sizeof (fd_set) / sizeof (__fd_mask); ++__i) \
        __FDS_BITS (__arr)[__i] = 0;                        \
    } while (0)

#define __FD_ELT(d)     ((d) / __NFDBITS)
#define __FD_MASK(d)    ((__fd_mask)1 << ((d) % __NFDBITS))

#define __FD_SET(d, set)                                    \
  ((void)(__FDS_BITS(set)[__FD_ELT(d)] |= __FD_MASK(d)))
#define __FD_CLR(d, set)                                    \
  ((void)(__FDS_BITS(set)[__FD_ELT(d)] &= ~__FD_MASK(d)))
#define __FD_ISSET(d, set)                                  \
  ((__FDS_BITS(set)[__FD_ELT(d)] & __FD_MASK(d)) != 0)

DEFINE_PROFILE_CATEGORY(select, );
DEFINE_PROFILE_INTERVAL(select_tryalloca_1, select);
DEFINE_PROFILE_INTERVAL(select_setup_array, select);
DEFINE_PROFILE_INTERVAL(select_do_poll, select);
DEFINE_PROFILE_INTERVAL(select_fd_zero, select);
DEFINE_PROFILE_INTERVAL(select_fd_sets, select);
DEFINE_PROFILE_INTERVAL(select_try_free, select);

int shim_do_select (int nfds, fd_set * readfds, fd_set * writefds,
                    fd_set * errorfds, struct __kernel_timeval * tsv)
{
    BEGIN_PROFILE_INTERVAL();

    if (!nfds) {
        if (!tsv)
            return -EINVAL;

        struct __kernel_timespec tsp;
        tsp.tv_sec = tsv->tv_sec;
        tsp.tv_nsec = tsv->tv_usec * 1000;
        return shim_do_nanosleep (&tsp, NULL);
    }

    struct shim_thread * cur = get_cur_thread();

    struct poll_handle * polls =
            __try_alloca(cur, sizeof(struct poll_handle) * nfds);
    int npolls = 0;

    SAVE_PROFILE_INTERVAL(select_tryalloca_1);

    for (int fd = 0 ; fd < nfds ; fd++) {
        bool do_r = (readfds  && __FD_ISSET(fd, readfds));
        bool do_w = (writefds && __FD_ISSET(fd, writefds));
        if (!do_r && !do_w)
            continue;
        debug("poll fd %d %s%s\n", fd, do_r ? "R" : "", do_w ? "W" : "");
        polls[npolls].fd = fd;
        polls[npolls].flags = (do_r ? DO_R : 0)|(do_w ? DO_W : 0);
        npolls++;
    }

    SAVE_PROFILE_INTERVAL(select_setup_array);

    uint64_t timeout_us = tsv ? tsv->tv_sec * 1000000ULL + tsv->tv_usec : POLL_NOTIMEOUT;
    int ret = __do_poll(npolls, polls, timeout_us);

    SAVE_PROFILE_INTERVAL(select_do_poll);

    if (ret < 0)
        goto out;

    ret = 0;

    if (readfds)
        __FD_ZERO(readfds);
    if (writefds)
        __FD_ZERO(writefds);
    if (errorfds)
        __FD_ZERO(errorfds);

    SAVE_PROFILE_INTERVAL(select_fd_zero);

    for (int i = 0 ; i < npolls ; i++) {
        if (readfds && ((polls[i].flags & (DO_R|RET_R)) == (DO_R|RET_R))) {
            __FD_SET(polls[i].fd, readfds);
            ret++;
        }
        if (writefds && ((polls[i].flags & (DO_W|RET_W)) == (DO_W|RET_W))) {
            __FD_SET(polls[i].fd, writefds);
            ret++;
        }
        if (errorfds && ((polls[i].flags & (DO_R|DO_W|RET_E)) > RET_E)) {
            __FD_SET(polls[i].fd, errorfds);
            ret++;
        }
    }
    SAVE_PROFILE_INTERVAL(select_fd_sets);

out:
    __try_free(cur, polls);
    SAVE_PROFILE_INTERVAL(select_try_free);
    return ret;
}

int shim_do_pselect6 (int nfds, fd_set * readfds, fd_set * writefds,
                      fd_set * errorfds, const struct __kernel_timespec * tsp,
                      const __sigset_t * sigmask)
{
    __UNUSED(sigmask);
    if (!nfds)
        return tsp ? shim_do_nanosleep (tsp, NULL) : -EINVAL;

    struct shim_thread * cur = get_cur_thread();

    struct poll_handle * polls =
            __try_alloca(cur, sizeof(struct poll_handle) * nfds);
    int npolls = 0;

    for (int fd = 0 ; fd < nfds ; fd++) {
        bool do_r = (readfds  && __FD_ISSET(fd, readfds));
        bool do_w = (writefds && __FD_ISSET(fd, writefds));
        if (!do_r && !do_w)
            continue;
        polls[npolls].fd = fd;
        polls[npolls].flags = (do_r ? DO_R : 0)|(do_w ? DO_W : 0);
        npolls++;
    }

    uint64_t timeout_us = tsp ? tsp->tv_sec * 1000000ULL + tsp->tv_nsec / 1000 : POLL_NOTIMEOUT;
    int ret = __do_poll(npolls, polls, timeout_us);

    if (ret < 0)
        goto out;

    ret = 0;

    if (readfds)
        __FD_ZERO(readfds);
    if (writefds)
        __FD_ZERO(writefds);
    if (errorfds)
        __FD_ZERO(errorfds);

    for (int i = 0 ; i < npolls ; i++) {
        if (readfds && ((polls[i].flags & (DO_R|RET_R)) == (DO_R|RET_R))) {
            __FD_SET(polls[i].fd, readfds);
            ret++;
        }
        if (writefds && ((polls[i].flags & (DO_W|RET_W)) == (DO_W|RET_W))) {
            __FD_SET(polls[i].fd, writefds);
            ret++;
        }
        if (errorfds && ((polls[i].flags & (DO_R|DO_W|RET_E)) > RET_E)) {
            __FD_SET(polls[i].fd, errorfds);
            ret++;
        }
    }

out:
    __try_free(cur, polls);
    return ret;
}
