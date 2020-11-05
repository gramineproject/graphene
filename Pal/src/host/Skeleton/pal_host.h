/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_HOST_H
#define PAL_HOST_H

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

typedef struct mutex_handle {
    int unused;
} PAL_LOCK;

#define LOCK_INIT {}
#define INIT_LOCK(lock) do {} while (0)

/* Locking and unlocking of mutexes */
int _DkMutexLock(struct mutex_handle* mut);
int _DkMutexLockTimeout(struct mutex_handle* mut, int64_t timeout_us);
int _DkMutexUnlock(struct mutex_handle* mut);

typedef struct pal_handle {
    /* TSAI: Here we define the internal types of PAL_HANDLE in PAL design, user has not to access
     * the content inside the handle, also there is no need to allocate the internal handles, so we
     * hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;

    union {
        struct {
            PAL_IDX fds[MAX_FDS];
        } generic;

        /* DP: Here we just define a placeholder fd; place your details here. Not every type
         * requires an fd either - this is up to your host-specific code.
         */
        struct {
            PAL_IDX fd;
        } file;

        struct {
            PAL_IDX fd;
        } pipe;

        struct {
            PAL_IDX fd;
        } pipeprv;

        struct {
            PAL_IDX unused;
        } eventfd;

        struct {
            PAL_IDX fd;
        } dev;

        struct {
            PAL_IDX fd;
        } dir;

        struct {
            PAL_IDX fd;
        } sock;

        struct {
            PAL_IDX unused;
        } process;

        struct {
            PAL_IDX unused;
        } thread;

        struct {
            PAL_IDX fd;
        } mutex;

        struct {
            PAL_IDX fd;
        } event;
    };
} * PAL_HANDLE;

#endif /* PAL_HOST_H */
