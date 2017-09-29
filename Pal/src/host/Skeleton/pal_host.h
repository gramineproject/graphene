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
 * pal_host.h
 *
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_HOST_H
#define PAL_HOST_H

#ifndef IN_PAL
# error "cannot be included outside PAL"
#endif

typedef int PAL_LOCK;
#define LOCK_INIT   (0)

typedef union pal_handle
{
    /* TSAI: Here we define the internal types of PAL_HANDLE
     * in PAL design, user has not to access the content inside the
     * handle, also there is no need to allocate the internal
     * handles, so we hide the type name of these handles on purpose.
     */

    struct {
        PAL_IDX type;
        PAL_FLG flags;
        PAL_IDX fds[];
    } hdr;

    struct {
        PAL_HDR reserved;
    } file;

    struct {
        PAL_HDR reserved;
    } pipe;

    struct {
        PAL_HDR reserved;
    } pipeprv;

    struct {
        PAL_HDR reserved;
        PAL_IDX dev_type;
    } dev;

    struct {
        PAL_HDR reserved;
    } dir;

    struct {
        PAL_HDR reserved;
    } gipc;

    struct {
        PAL_HDR reserved;
    } sock;

    struct {
        PAL_HDR reserved;
    } process;

    struct {
        PAL_HDR reserved;
    } mcast;

    struct {
        PAL_HDR reserved;
    } thread;

    struct {
        PAL_HDR reserved;
    } semaphore;

    struct {
        PAL_HDR reserved;
    } event;
} * PAL_HANDLE;

#endif /* PAL_HOST_H */
