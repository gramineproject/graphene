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
 * pal_host.h
 *
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
            PAL_IDX dev_type;
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
