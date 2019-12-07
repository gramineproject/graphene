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
 * Implementation of system calls "poll", "ppoll", "select" and "pselect6".
 */

#include <errno.h>
#include <linux/fcntl.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

typedef long int __fd_mask;

#ifndef __NFDBITS
#define __NFDBITS    (8 * (int)sizeof(__fd_mask))
#endif
#ifndef __FDS_BITS
#define __FDS_BITS(set) ((set)->fds_bits)
#endif

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

#define POLL_NOTIMEOUT  ((uint64_t)-1)

int shim_do_poll(struct pollfd* fds, nfds_t nfds, int timeout_ms) {
    if (!fds || test_user_memory(fds, sizeof(*fds) * nfds, true))
        return -EFAULT;

    if ((uint64_t)nfds > get_rlimit_cur(RLIMIT_NOFILE))
        return -EINVAL;

    struct shim_handle_map* map = get_cur_thread()->handle_map;

    uint64_t timeout_us = timeout_ms < 0 ? POLL_NOTIMEOUT : timeout_ms * 1000ULL;

    /* nfds is the upper limit for actual number of handles */
    PAL_HANDLE* pals = malloc(nfds * sizeof(PAL_HANDLE));
    if (!pals)
        return -ENOMEM;

    /* for bookkeeping, need to have a mapping FD -> handle */
    struct shim_handle** fds_to_hdls = malloc(nfds * sizeof(struct shim_handle*));
    if (!fds_to_hdls) {
        free(pals);
        return -ENOMEM;
    }

    nfds_t npals = 0;
    nfds_t nrevents = 0;

    lock(&map->lock);

    /* collect PAL handles that correspond to user-supplied FDs (only those that can be polled) */
    for (nfds_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        fds_to_hdls[i] = NULL;

        if (fds[i].fd < 0) {
            /* FD is negative, must be ignored */
            continue;
        }

        if (!(fds[i].events & (POLLIN|POLLRDNORM)) &&
            !(fds[i].events & (POLLOUT|POLLWRNORM))) {
            /* user didn't ask for read or write, ignore this FD */
            continue;
        }

        struct shim_handle* hdl = __get_fd_handle(fds[i].fd, NULL, map);
        if (!hdl || !hdl->fs || !hdl->fs->fs_ops) {
            /* the corresponding handle doesn't exist or doesn't provide FS-like semantics */
            continue;
        }

        int allowed_events = 2; /* read + write */
        if ((fds[i].events & (POLLIN|POLLRDNORM)) && !(hdl->acc_mode & MAY_READ))
            allowed_events -= 1; /* minus read */
        if ((fds[i].events & (POLLOUT|POLLWRNORM)) && !(hdl->acc_mode & MAY_WRITE))
            allowed_events -= 1; /* minus write */
        if (!allowed_events) {
            /* the corresponding handle cannot be read or written */
            continue;
        }

        if (!(fds[i].events & (POLLIN|POLLRDNORM)) && (fds[i].events & (POLLOUT|POLLWRNORM))) {
            /* special case: user is interested only in write event on this handle, and whether
             * write event occurs is always known in PAL layer, so simply consult PAL and
             * update revents and skip this handle for polling (note that otherwise PAL could get
             * stuck in host poll() because PAL always polls on read events) */
            PAL_STREAM_ATTR attr;
            if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr)) {
                /* something went wrong with this handle, silently skip this handle */
                continue;
            }

            if (attr.writable)
                fds[i].revents |= (fds[i].events & (POLLOUT|POLLWRNORM));
            if (attr.disconnected)
                fds[i].revents |= (POLLERR|POLLHUP);

            if (fds[i].revents)
                nrevents++;
            continue;
        }

        get_handle(hdl);
        fds_to_hdls[i] = hdl;
        pals[npals]    = hdl->pal_handle;
        npals++;
    }

    unlock(&map->lock);

    /* TODO: This loop is highly inefficient, since DkObjectsWaitAny returns only one (random)
     *       handle out of the whole array of handles-waiting-for-events. We must replace this
     *       loop with a single DkObjectsWaitEvents(). */
    while (npals) {
        PAL_HANDLE polled = DkObjectsWaitAny(npals, pals, timeout_us);
        if (!polled)
            break;

        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQueryByHandle(polled, &attr))
            continue;

        for (nfds_t i = 0; i < nfds; i++) {
            if (fds_to_hdls[i]->pal_handle == polled) {
                /* found user-supplied FD, update it with returned events */
                fds[i].revents = 0;
                if (attr.readable)
                    fds[i].revents |= (fds[i].events & (POLLIN|POLLRDNORM));
                if (attr.writable)
                    fds[i].revents |= (fds[i].events & (POLLOUT|POLLWRNORM));
                if (attr.disconnected)
                    fds[i].revents |= (POLLERR|POLLHUP);

                if (fds[i].revents)
                    nrevents++;
                break;
            }
        }

        /* done with this PAL handle, remove it from array on which to DkObjectsWaitAny */
        nfds_t skip = 0;
        for (nfds_t i = 0; i < npals; i++) {
            if (pals[i] == polled)
                skip = 1;
            else
                pals[i - skip] = pals[i];
        }
        npals -= skip;
    }

    for (nfds_t i = 0; i < nfds; i++)
        if (fds_to_hdls[i])
            put_handle(fds_to_hdls[i]);
    free(pals);
    free(fds_to_hdls);

    return nrevents;
}

int shim_do_ppoll(struct pollfd* fds, int nfds, struct timespec* tsp,
                  const __sigset_t* sigmask, size_t sigsetsize) {
    __UNUSED(sigmask);
    __UNUSED(sigsetsize);

    uint64_t timeout_ms = tsp ? tsp->tv_sec * 1000ULL + tsp->tv_nsec / 1000000 : POLL_NOTIMEOUT;
    return shim_do_poll(fds, nfds, timeout_ms);
}

int shim_do_select(int nfds, fd_set* readfds, fd_set* writefds,
                   fd_set* errorfds, struct __kernel_timeval* tsv) {
    if (tsv && (tsv->tv_sec < 0 || tsv->tv_usec < 0))
            return -EINVAL;

    if (nfds < 0 || (uint64_t)nfds > get_rlimit_cur(RLIMIT_NOFILE))
        return -EINVAL;

    if (!nfds) {
        if (!tsv)
            return -EINVAL;

        /* special case of select(0, ..., tsv) used for sleep */
        struct __kernel_timespec tsp;
        tsp.tv_sec = tsv->tv_sec;
        tsp.tv_nsec = tsv->tv_usec * 1000;
        return shim_do_nanosleep(&tsp, NULL);
    }

    if (nfds < __NFDBITS) {
        /* interesting corner case: Linux always checks at least 64 first FDs */
        nfds = __NFDBITS;
    }

    /* nfds is the upper limit for actual number of fds for poll */
    struct pollfd* fds_poll = malloc(nfds * sizeof(struct pollfd));
    if (!fds_poll)
        return -ENOMEM;

    /* populate array of pollfd's based on user-supplied readfds & writefds */
    nfds_t nfds_poll = 0;
    for (int fd = 0; fd < nfds; fd++) {
        short events = 0;
        if (readfds && __FD_ISSET(fd, readfds))
            events |= POLLIN;
        if (writefds && __FD_ISSET(fd, writefds))
            events |= POLLOUT;

        if (!events)
            continue;

        fds_poll[nfds_poll].fd      = fd;
        fds_poll[nfds_poll].events  = events;
        fds_poll[nfds_poll].revents = 0;
        nfds_poll++;
    }

    /* select()/pselect() return -EBADF if invalid FD was given by user in readfds/writefds;
     * note that poll()/ppoll() don't have this error code, so we return this code only here */
    struct shim_handle_map* map = get_cur_thread()->handle_map;
    lock(&map->lock);
    for (nfds_t i = 0; i < nfds_poll; i++) {
        struct shim_handle* hdl = __get_fd_handle(fds_poll[i].fd, NULL, map);
        if (!hdl || !hdl->fs || !hdl->fs->fs_ops) {
            /* the corresponding handle doesn't exist or doesn't provide FS-like semantics */
            free(fds_poll);
            unlock(&map->lock);
            return -EBADF;
        }
    }
    unlock(&map->lock);

    uint64_t timeout_ms = tsv ? tsv->tv_sec * 1000ULL + tsv->tv_usec / 1000 : POLL_NOTIMEOUT;
    int ret = shim_do_poll(fds_poll, nfds_poll, timeout_ms);

    if (ret < 0) {
        free(fds_poll);
        return ret;
    }

    /* modify readfds, writefds, and errorfds in-place with returned events */
    if (readfds)
        __FD_ZERO(readfds);
    if (writefds)
        __FD_ZERO(writefds);
    if (errorfds)
        __FD_ZERO(errorfds);

    ret = 0;
    for (nfds_t i = 0; i < nfds_poll; i++) {
        if (readfds && (fds_poll[i].revents & POLLIN)) {
            __FD_SET(fds_poll[i].fd, readfds);
            ret++;
        }
        if (writefds && (fds_poll[i].revents & POLLOUT)) {
            __FD_SET(fds_poll[i].fd, writefds);
            ret++;
        }
        if (errorfds && (fds_poll[i].revents & POLLERR)) {
            __FD_SET(fds_poll[i].fd, errorfds);
            ret++;
        }
    }

    free(fds_poll);
    return ret;
}

int shim_do_pselect6(int nfds, fd_set* readfds, fd_set* writefds,
                     fd_set* errorfds, const struct __kernel_timespec* tsp,
                     const __sigset_t* sigmask) {
    __UNUSED(sigmask);

    if (tsp) {
        struct __kernel_timeval tsv;
        tsv.tv_sec = tsp->tv_sec;
        tsv.tv_usec = tsp->tv_nsec / 1000;
        return shim_do_select(nfds, readfds, writefds, errorfds, &tsv);
    }

    return shim_do_select(nfds, readfds, writefds, errorfds, NULL);
}
