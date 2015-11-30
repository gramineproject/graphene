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
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>
#include <bits/dlfcn.h>

PAL_CONTROL __pal_control;
PAL_CONTROL * pal_control_addr (void)
{
    return &__pal_control;
}

struct pal_internal_state pal_state;

static void load_libraries (void)
{
    /* we will not make any assumption for where the libraries are loaded */
    char cfgbuf[CONFIG_MAX];
    int len, ret = 0;

    /* loader.preload:
       any other libraries to preload. The can be multiple URIs,
       seperated by commas */
    len = get_config(pal_state.root_config, "loader.preload", cfgbuf,
                     CONFIG_MAX);
    if (len <= 0)
        return;

    char * c = cfgbuf, * library_name = c;
    for (;; c++)
        if (*c == ',' || !(*c)) {
            if (c > library_name) {
#if PROFILING == 1
                unsigned long before_load_library = _DkSystemTimeQuery();
#endif

                *c = 0;
                if ((ret = load_elf_object(library_name, OBJECT_PRELOAD)) < 0)
                    init_fail(-ret, "Unable to load preload library");

#if PROFILING == 1
                pal_state.linking_time +=
                        _DkSystemTimeQuery() - before_load_library;
#endif
            }

            if (c == cfgbuf + len)
                break;

            library_name = c + 1;
        }
}

static void read_envs (const char *** envpp)
{
    const char ** envp = *envpp;
    char cfgbuf[CONFIG_MAX];

   /* loader.env.* and loader.exclude.env: filtering host environment
     * variables */
   struct env {
        const char * str;
        int len, idx;
    } * envs = NULL;
    int nenvs = 0;

    if (pal_state.root_config)
        nenvs = get_config_entries(pal_state.root_config, "loader.env",
                                   cfgbuf, CONFIG_MAX);

    if (nenvs > 0) {
        envs = __alloca(sizeof(struct env) * nenvs);
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
    }

    int envc = 0, add = nenvs;
    for (const char ** e = envp ; *e ; e++) {
        const char * s = *e, * p = s;
        envc++;
        while (*p && *p != '=')
            p++;
        int l = p - s;
        const char * v = p + 1;

        if (l > 8 &&
            s[0] == 'P' && s[1] == 'A' && s[2] == 'L' && s[3] == '_' &&
            s[4] == 'L' && s[5] == 'O' && s[6] == 'G' && s[7] == '_') {
            /* PAL_LOG_STREAM = */
            if (l == 14 && s[8] == 'S' && s[9] == 'T' &&
                s[10] == 'R' && s[11] == 'E' && s[12] == 'A' && s[13] == 'M') {
                PAL_HANDLE log;
                if (!_DkStreamOpen(&log, v, PAL_ACCESS_APPEND,
                                   PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                                   PAL_CREAT_TRY, 0)) {
                    if (pal_state.log_stream)
                        _DkObjectClose(pal_state.log_stream);
                    pal_state.log_stream = log;
                }
            }

            /* PAL_LOG_TYPES = */
            if (l == 13 && s[8] == 'T' && s[9] == 'Y' &&
                s[10] == 'P' && s[11] == 'E' && s[12] == 'S') {
                const char * t = v, * n;
                while (*t) {
                    for (n = t ; *n && *n != ',' ; n++);
                    switch (n - t) {
                        case 4:
                            if (t[0] == 'f' && t[1] == 'i' && t[2] == 'l' &&
                                t[3] == 'e')
                                pal_state.log_types |= LOG_FILE;
                            if (t[0] == 'p' && t[1] == 'i' && t[2] == 'p' &&
                                t[3] == 'e')
                                pal_state.log_types |= LOG_PIPE;
                            break;
                        case 6:
                            if (t[0] == 's' && t[1] == 'o' && t[2] == 'c' &&
                                t[3] == 'k' && t[4] == 'e' && t[5] == 't')
                                pal_state.log_types |= LOG_SOCKET;
                            break;
                    }
                    t = *n ? n + 1 : n;
                }
            }

            continue;
        }

        for (int i = 0 ; i < nenvs ; i++)
            if (envs[i].len == l && !memcmp(envs[i].str, s, l)) {
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
        if ((bytes = get_config(pal_state.root_config, key, cfgbuf,
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

    *envpp = envp;
}

static void set_debug_type (void)
{
    char cfgbuf[CONFIG_MAX];
    int ret;

    if (!pal_state.root_config)
        return;

    ret = get_config(pal_state.root_config, "loader.debug_type",
                     cfgbuf, CONFIG_MAX);
    if (ret <= 0)
        return;

    PAL_HANDLE handle = NULL;

    if (!memcmp(cfgbuf, "inline", 7)) {
        ret = _DkStreamOpen(&handle, "dev:tty", PAL_ACCESS_RDWR, 0, 0, 0);
        if (ret < 0)
            init_fail(-ret, "cannot open debug stream");
    } else if (!memcmp(cfgbuf, "file", 5)) {
        ret = get_config(pal_state.root_config, "loader.debug_file",
                         cfgbuf, CONFIG_MAX);
        if (ret <= 0)
            init_fail(PAL_ERROR_INVAL, "debug file not specified");

        ret = _DkStreamOpen(&handle, cfgbuf,
                            PAL_ACCESS_RDWR,
                            PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                            PAL_CREAT_TRY, 0);
        if (ret < 0)
            init_fail(-ret, "cannot open debug file");
    } else if (memcmp(cfgbuf, "none", 5)) {
        init_fail(PAL_ERROR_INVAL, "unknown debug type");
    }

    __pal_control.debug_stream = handle;
}

static void set_syscall_symbol (void)
{
    char cfgbuf[CONFIG_MAX];
    int ret;

    if (!pal_state.root_config)
        return;

    ret = get_config(pal_state.root_config, "loader.syscall_symbol",
                     cfgbuf, CONFIG_MAX);
    if (ret <= 0)
        return;

    pal_state.syscall_sym_name = remalloc(cfgbuf, ret + 1);
}

static int loader_filter (const char * key, int len)
{
    return (key[0] == 'l' && key[1] == 'o' && key[2] == 'a' && key[3] == 'd' &&
            key[4] == 'e' && key[5] == 'r' && key[6] == '.') ? 0 : 1;
}

void pal_main (PAL_NUM pal_token, void * pal_addr,
               const char * pal_name,
               int argc, const char ** argv, const char ** envp,
               PAL_HANDLE parent_handle,
               PAL_HANDLE thread_handle,
               PAL_HANDLE exec_handle,
               PAL_HANDLE manifest_handle)
{
    int ret;
    bool is_parent = !parent_handle;

#if PROFILING == 1
    __pal_control.host_specific_startup_time =
            _DkSystemTimeQuery() - pal_state.start_time;
#endif

    pal_state.pal_token     = pal_token;
    pal_state.pal_addr      = pal_addr;
    pal_state.parent_handle = parent_handle;
    pal_state.pagesize      = _DkGetPagesize();
    pal_state.alloc_align   = _DkGetAllocationAlignment();
    pal_state.alloc_shift   = pal_state.alloc_align - 1;
    pal_state.alloc_mask    = ~pal_state.alloc_shift;

    init_slab_mgr(pal_state.alloc_align);

    if (is_parent && !exec_handle && !manifest_handle) {
        printf("USAGE: %s [executable|manifest] args ...\n", pal_name);
        _DkProcessExit(0);
        return;
    }

    char * exec = NULL, * manifest = NULL;

    if (exec_handle) {
        exec = __alloca(URI_MAX);
        ret = _DkStreamGetName(exec_handle, exec, URI_MAX);
        if (ret < 0)
            init_fail(-ret, "cannot get executable name");
    }

    if (manifest_handle) {
        manifest = __alloca(URI_MAX);
        ret = _DkStreamGetName(manifest_handle, manifest, URI_MAX);
        if (ret < 0)
            init_fail(-ret, "cannot get manifest name");
    } else {
        if (is_parent) {
#if PROFILING == 1
            unsigned long before_find_manifest = _DkSystemTimeQuery();
#endif
            do {
                assert(!!exec);
                /* try open "<exec>.manifest" */
                manifest = __alloca(URI_MAX);
                snprintf(manifest, URI_MAX, "%s.manifest", exec);
                ret = _DkStreamOpen(&manifest_handle,
                                    manifest,
                                    PAL_ACCESS_RDONLY, 0, 0, 0);
                if (!ret)
                    break;

                /* try open "file:manifest" */
                manifest = "file:manifest";
                ret = _DkStreamOpen(&manifest_handle,
                                    manifest,
                                    PAL_ACCESS_RDONLY, 0, 0, 0);
                if (!ret)
                    break;

                /* well, there is no manifest file, leave it alone */
                if (!manifest_handle)
                    printf("Can't fine any manifest, will run without one\n");
            } while (0);

#if PROFILING == 1
            pal_state.manifest_loading_time +=
                            _DkSystemTimeQuery() - before_find_manifest;
#endif
        }
    }

    /* load manifest if there is one */
    if (manifest_handle) {
#if PROFILING == 1
        unsigned long before_load_manifest = _DkSystemTimeQuery();
#endif

        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuerybyHandle(manifest_handle, &attr);
        if (ret < 0)
            init_fail(-ret, "cannot open manifest file");

        void * cfg_addr = NULL;
        int cfg_size = attr.pending_size;

        ret = _DkStreamMap(manifest_handle, &cfg_addr,
                           PAL_PROT_READ, 0,
                           ALLOC_ALIGNUP(cfg_size));
        if (ret < 0)
            init_fail(-ret, "cannot open manifest file");

        struct config_store * root_config = malloc(sizeof(struct config_store));
        root_config->raw_data = cfg_addr;
        root_config->raw_size = cfg_size;
        root_config->malloc = malloc;
        root_config->free = free;

        const char * errstring = NULL;
        if ((ret = read_config(root_config, loader_filter, &errstring)) < 0)
            init_fail(-ret, errstring);

        pal_state.root_config = root_config;

#if PROFILING == 1
        pal_state.manifest_loading_time +=
                        _DkSystemTimeQuery() - before_load_manifest;
#endif
    }

    /* if there is no executable, try to find one in the manifest */
    if (is_parent && !exec_handle) {
        exec = __alloca(URI_MAX);
        assert(!!pal_state.root_config);

        ret = get_config(pal_state.root_config, "loader.exec", exec, URI_MAX);
        if (ret > 0) {
            ret = _DkStreamOpen(&exec_handle, exec, PAL_ACCESS_RDONLY,
                                0, 0, 0);
            if (ret < 0)
                init_fail(-ret, "cannot open executable");

            /* must be a ELF */
            if (check_elf_object(exec_handle) < 0)
                init_fail(PAL_ERROR_INVAL, "executable is not a ELF binary");
        } else {
            exec = NULL;
        }
    }

    pal_state.manifest        = manifest;
    pal_state.manifest_handle = manifest_handle;
    pal_state.exec            = exec;
    pal_state.exec_handle     = exec_handle;

    const char * first_argv = *argv;
    argc--;
    argv++;

    if (is_parent && exec) {
        first_argv = exec;
        if (pal_state.root_config) {
            char cfgbuf[CONFIG_MAX];
            ret = get_config(pal_state.root_config, "loader.execname", cfgbuf,
                             CONFIG_MAX);
            if (ret > 0)
                first_argv = remalloc(cfgbuf, ret + 1);
        }
    }

    read_envs(&envp);

    if (pal_state.log_stream && (pal_state.log_types & LOG_FILE)) {
        if (manifest)
            log_stream(manifest);
        if (exec)
            log_stream(exec);
    }

    if (pal_state.root_config)
        load_libraries();

    if (exec_handle) {
#if PROFILING == 1
        unsigned long before_load_exec = _DkSystemTimeQuery();
#endif

        ret = load_elf_object_by_handle(exec_handle, OBJECT_EXEC);
        if (ret < 0)
            init_fail(ret, PAL_STRERROR(ret));

#if PROFILING == 1
        pal_state.linking_time += _DkSystemTimeQuery() - before_load_exec;
#endif
    }

#if PROFILING == 1
    unsigned long before_tail = _DkSystemTimeQuery();
#endif

    set_debug_type();
    set_syscall_symbol();

    __pal_control.process_id         = _DkGetProcessId();
    __pal_control.host_id            = _DkGetHostId();
    __pal_control.manifest_handle    = manifest_handle;
    __pal_control.executable         = exec;
    __pal_control.parent_process     = parent_handle;
    __pal_control.first_thread       = thread_handle;

    _DkGetAvailableUserAddressRange(&__pal_control.user_address.start,
                                    &__pal_control.user_address.end);

    __pal_control.pagesize           = pal_state.pagesize;
    __pal_control.alloc_align        = pal_state.alloc_align;
    __pal_control.broadcast_stream   = _DkBroadcastStreamOpen();

    _DkGetCPUInfo(&__pal_control.cpu_info);
    __pal_control.mem_info.mem_total = _DkMemoryQuota();

#if PROFILING == 1
    pal_state.tail_startup_time      += _DkSystemTimeQuery() - before_tail;

    __pal_control.relocation_time     = pal_state.relocation_time;
    __pal_control.linking_time        = pal_state.linking_time;
    __pal_control.manifest_loading_time
                                      = pal_state.manifest_loading_time;
    __pal_control.allocation_time     = pal_state.slab_time;
    __pal_control.child_creation_time = is_parent ? 0 : pal_state.start_time -
                                        pal_state.process_create_time;
#endif

    /* Now we will start the execution */
    start_execution(first_argv, argc, argv, envp);

    /* We wish we will never reached here */
    init_fail(PAL_ERROR_DENIED, "unexpected termination");
}

void write_log (int nstrs, ...)
{
    const char ** strs = __alloca(sizeof(const char *) * nstrs);
    int len = 0;
    va_list ap;

    va_start(ap, nstrs);
    for (int i = 0 ; i < nstrs ; i++) {
        strs[i] = va_arg(ap, const char *);
        len += strlen(strs[i]);
    }
    va_end(ap);

    char * buf = __alloca(len);
    int cnt = 0;

    for (int i = 0 ; i < nstrs ; i++) {
        int l = strlen(strs[i]);
        memcpy(buf + cnt, strs[i], l);
        cnt += l;
    }

    _DkStreamWrite(pal_state.log_stream, 0, cnt, buf, NULL, 0);
}
