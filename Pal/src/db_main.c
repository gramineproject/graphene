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
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_security.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>
#include <bits/dlfcn.h>

/* allocate memory for page size constants */
PAL_NUM allocsize, allocshift, allocmask;

PAL_CONTROL __pal_control;
PAL_CONTROL * pal_control_addr (void)
{
    return &__pal_control;
}

/* initialize the value of pal_config attributes */
struct pal_config pal_config;
struct pal_sec_info pal_sec_info;

#define leave \
    do { printf("PAL terminated at " __FILE__ ":%d\n", __LINE__); \
         _DkProcessExit(1); } while (0)

int load_libraries (struct config_store * root_config, const char ** msg)
{
    /* we will not make any assumption for where the libraries are loaded */
    char cfgbuf[CONFIG_MAX];
    int len, ret = 0;

    /* loader.preload: any other libraries to preload. The can be multiple
       URIs, seperated by commas */
    if ((len = get_config(root_config, "loader.preload", cfgbuf,
                          CONFIG_MAX)) > 0) {
        char * c = cfgbuf, * token = c;
        do {
            if (*c == ',' || !(*(c))) {
                if (c > token) {
                    *c = 0;
                    if ((ret = load_elf_object(token, OBJECT_PRELOAD)) < 0) {
                        if (msg)
                            *msg = "Unable to load preload library\n";
                        return ret;
                    }
                }

                token = c + 1;
            }
        } while (*(c++));
    }

    return 0;
}

static void read_envs (const char ** envp)
{
    if (!pal_config.root_config)
        goto done;

    char cfgbuf[CONFIG_MAX];

   /* loader.env.* and loader.exclude.env: filtering host environment
     * variables */
    int nenvs = get_config_entries(pal_config.root_config, "loader.env", cfgbuf,
                                   CONFIG_MAX);

    if (nenvs > 0) {
        struct env { const char * str; int len, idx; } * envs
                                    = __alloca(sizeof(struct env) * nenvs);
        char * cfg = cfgbuf;
        for (int i = 0 ; i < nenvs ; i++) {
            int len = strlen(cfg);
            char * str = __alloca(len + 1);
            envs[i].str = str;
            envs[i].len = len;
            envs[i].idx = -1;
            memcpy(str, cfg, len + 1);
            cfg += len + 1;
        }

        int envc = 0, add = nenvs;
        for (const char ** e = envp ; *e ; e++) {
            envc++;
            const char * p = *e;
            while (*p && *p != '=')
                p++;

            for (int i = 0 ; i < nenvs ; i++)
                if (envs[i].len == p - *e && !memcmp(envs[i].str, *e, p - *e)) {
                    envs[i].idx = envc - 1;
                    add--;
                    break;
                }
        }

        if (add) {
            const char ** new_envp =
                        malloc(sizeof(const char *) * (envc + add + 1));
            memcpy(new_envp, envp, sizeof(const char *) * envc);
            envp = new_envp;
            envp[envc + add] = NULL;
        }

        char key[CONFIG_MAX] = "loader.env.";
        const char ** ptr;

        for (int i = 0 ; i < nenvs ; i++) {
            const char * str = envs[i].str;
            int len = envs[i].len;
            int idx = envs[i].idx;
            int bytes;
            ptr = &envp[(idx == -1) ? envc++ : idx];
            memcpy(key + 11, str, len + 1);
            if ((bytes = get_config(pal_config.root_config, key, cfgbuf,
                                    CONFIG_MAX)) > 0) {
                char * e = malloc(len + bytes + 2);
                memcpy(e, str, len);
                e[len] = '=';
                memcpy(e + len + 1, cfgbuf, bytes + 1);
                *ptr = e;
            } else {
                char * e = malloc(len + 2);
                memcpy(e, str, len);
                e[len] = '=';
                e[len + 1] = 0;
                *ptr = e;
            }
        }
    }

done:
    pal_config.environments = envp;
}

static void * find_heap_base (void)
{
    /* This function is to allocate an area to map preloaded loibraries,
       but try to get around future address of PAL caused by ASLR.
       The top of heap must be at least 1/16 of the area below where PAL
       is loaded. The address is still randomized. */
    unsigned long heap_base = (unsigned long) pal_config.lib_text_start;
    unsigned long pal_size = pal_config.lib_data_end -
                             pal_config.lib_text_start;
    unsigned long base = allocsize;

    while ((base >> 12) < pal_size)
        base <<= 1;
    while ((base << 6) < heap_base)
        base <<= 1;

    heap_base &= allocmask;
    while ((heap_base -= base) > base) {
        void * heap = (void *) heap_base;
        if (!_DkVirtualMemoryAlloc(&heap, allocsize, PAL_ALLOC_RESERVE,
                                   PAL_PROT_NONE))
            return heap;
    }

    return NULL;
}

void start_execution (int argc, const char ** argv);

void pal_main (int argc, const char ** argv, const char ** envp)
{
    char cfgbuf[CONFIG_MAX];
    int ret;

    pal_config.pagesize    = _DkGetPagesize();
    pal_config.alloc_align = _DkGetAllocationAlignment();

    /* some constants for page manipulation and allocation alignment */
    allocsize  = pal_config.alloc_align;
    allocshift = allocsize - 1;
    allocmask  = ~allocshift;

    init_slab_mgr();

    /* reloaction of loader is done here. starting from this point, the global
       symbols of loader should be accessible. */
    pal_config.lib_text_start = (void *) &text_start;
    pal_config.lib_text_end   = (void *) &text_end;
    pal_config.lib_data_start = (void *) &data_start;
    pal_config.lib_data_end   = (void *) &data_end;

    __pal_control.pagesize      = pal_config.pagesize;
    __pal_control.alloc_align   = allocsize;
    __pal_control.library_begin = &text_start;
    __pal_control.library_end   = &data_end;

    /*
     * _DkInitHost must set up the following values:
     *     pal_config.manifest
     *     pal_config.manifest_handle
     *     pal_config.exec
     *     pal_config.exec_handle
     *     pal_config.root_config
     */
    if (_DkInitHost(&argc, &argv) < 0)
        leave;

    __pal_control.manifest_handle = pal_config.manifest_handle;
    __pal_control.executable = pal_config.exec;

    /* all of the preloaded libraries are loaded,
       time to play with executable */
    if (pal_config.exec_handle) {
        ret = load_elf_object_by_handle(pal_config.exec_handle, OBJECT_EXEC);

        if (ret < 0) {
            printf("Unable to load executable (%d)\n", PAL_STRERROR(ret));
            leave;
        }
    }

    read_envs(envp);

    if (!pal_config.heap_base)
        pal_config.heap_base = find_heap_base();

    if (pal_config.root_config) {
        struct config_store * cfg = pal_config.root_config;
        const char * msg;

        if (load_libraries(cfg, &msg) < 0) {
            printf("%s\n", msg);
            leave;
        }

        if (get_config(cfg, "loader.daemonize", cfgbuf,
                       CONFIG_MAX) > 0 &&
            cfgbuf[0] == '1' && !cfgbuf[1])
            pal_config.daemonize = true;

        if (get_config(cfg, "loader.debug_type", cfgbuf,
                       CONFIG_MAX) > 0) {
            PAL_HANDLE handle = NULL;

            if (!memcmp(cfgbuf, "inline", 7)) {
                _DkStreamOpen(&handle, "dev:tty", PAL_ACCESS_RDWR, 0, 0, 0);
            } else if (!memcmp(cfgbuf, "file", 5)) {
                if (get_config(cfg, "loader.debug_file", cfgbuf,
                               CONFIG_MAX) > 0) {
                    _DkStreamOpen(&handle, cfgbuf, PAL_ACCESS_RDWR,
                                  PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                                  PAL_CREAT_TRY, 0);
                }
            }

            __pal_control.debug_stream = handle;
        }

        if ((ret = get_config(cfg, "loader.syscall_symbol", cfgbuf,
                              CONFIG_MAX)) > 0)
            pal_config.syscall_sym_name = remalloc(cfgbuf, ret + 1);

        free_config(cfg);
        _DkStreamUnmap(cfg->raw_data, ALLOC_ALIGNUP(cfg->raw_size));
        free(cfg);
        pal_config.root_config = NULL;
    }

    __pal_control.manifest_handle = pal_config.manifest_handle;
    __pal_control.executable = pal_config.exec;

    /* Now we will start the execution */
    start_execution(argc, argv);

    /* We wish we will never reached here */
    printf("unexpected termination\n");
    leave;
}
