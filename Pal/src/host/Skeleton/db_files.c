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
 * db_files.c
 *
 * This file contains operands to handle streams with URIs that start with
 * "file:" or "dir:".
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

/* 'open' operation for file streams */
static int file_open (PAL_HANDLE * handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'read' operation for file streams. */
static int file_read (PAL_HANDLE handle, int offset, int count,
                      void * buffer)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'write' operation for file streams. */
static int file_write (PAL_HANDLE handle, int offset, int count,
                       const void * buffer)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'close' operation for file streams. In this case, it will only
   close the file withou deleting it. */
static int file_close (PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'delete' operation for file streams. It will actually delete
   the file if we can successfully close it. */
static int file_delete (PAL_HANDLE handle, int access)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'map' operation for file stream. */
static int file_map (PAL_HANDLE handle, void ** addr, int prot,
                     int offset, int size)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'setlength' operation for file stream. */
static int file_setlength (PAL_HANDLE handle, int length)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'flush' operation for file stream. */
static int file_flush (PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquery' operation for file streams */
static int file_attrquery (const char * type, const char * uri,
                           PAL_STREAM_ATTR * attr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquerybyhdl' operation for file streams */
static int file_attrquerybyhdl (PAL_HANDLE handle,
                                PAL_STREAM_ATTR * attr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_rename (PAL_HANDLE handle, const char * type,
                        const char * uri)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_getname (PAL_HANDLE handle, char * buffer, int count)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

const char * file_getrealpath (PAL_HANDLE handle)
{
    return NULL;
}

struct handle_ops file_ops = {
        .getname            = &file_getname,
        .getrealpath        = &file_getrealpath,
        .open               = &file_open,
        .read               = &file_read,
        .write              = &file_write,
        .close              = &file_close,
        .delete             = &file_delete,
        .map                = &file_map,
        .setlength          = &file_setlength,
        .flush              = &file_flush,
        .attrquery          = &file_attrquery,
        .attrquerybyhdl     = &file_attrquerybyhdl,
        .rename             = &file_rename,
    };

/* 'open' operation for directory stream. Directory stream does not have a
   specific type prefix, its URI looks the same file streams, plus it
   ended with slashes. dir_open will be called by file_open. */
static int dir_open (PAL_HANDLE * handle, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operat4on. */
int dir_read (PAL_HANDLE handle, int offset, int count, void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'close' operation of directory streams */
static int dir_close (PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'delete' operation of directoy streams */
static int dir_delete (PAL_HANDLE handle, int access)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* 'attrquerybyhdl' operation of directory streams */
static int dir_attrquerybyhdl (PAL_HANDLE handle,
                               PAL_STREAM_ATTR * attr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dir_rename (PAL_HANDLE handle, const char * type,
                       const char * uri)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dir_getname (PAL_HANDLE handle, char * buffer, int count)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static const char * dir_getrealpath (PAL_HANDLE handle)
{
    return NULL;
}

struct handle_ops dir_ops = {
        .getname            = &dir_getname,
        .getrealpath        = &dir_getrealpath,
        .open               = &dir_open,
        .read               = &dir_read,
        .close              = &dir_close,
        .delete             = &dir_delete,
        .attrquery          = &file_attrquery,
        .attrquerybyhdl     = &dir_attrquerybyhdl,
        .rename             = &dir_rename,
    };
