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
#include "pal_rtld.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>

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
    ssize_t len, ret = 0;

    /* loader.preload:
       any other libraries to preload. The can be multiple URIs,
       seperated by commas */
    len = get_config(pal_state.root_config, "loader.preload", cfgbuf,
                     sizeof(cfgbuf));
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
                    INIT_FAIL(-ret, "Unable to load preload library");

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

static void read_environments (const char *** envpp)
{
    struct config_store * store = pal_state.root_config;
    const char ** envp = *envpp;

    /* loader.env.*: rewriting host environment variables */
    struct setenv {
        const char * str;
        int len, idx;
    } * setenvs = NULL;
    int nsetenvs = 0;

    if (!pal_state.root_config)
        return;

    ssize_t cfgsize_envs = get_config_entries_size(store, "loader.env");
    /* XXX Propagate this error? */
    if (cfgsize_envs < 0)
        return;

    char * cfgbuf_envs = malloc(cfgsize_envs);
    assert(cfgbuf_envs);
    nsetenvs = get_config_entries(store, "loader.env", cfgbuf_envs, cfgsize_envs);
    if (nsetenvs <= 0) {
        free(cfgbuf_envs);
        return;
    }

    setenvs = __alloca(sizeof(struct setenv) * nsetenvs);
    char * cfg = cfgbuf_envs;
    for (int i = 0 ; i < nsetenvs ; i++) {
        size_t len = strlen(cfg);
        char * str = __alloca(len + 1);
        setenvs[i].str = str;
        setenvs[i].len = len;
        setenvs[i].idx = -1;
        memcpy(str, cfg, len + 1);
        cfg += len + 1;
    }
    free(cfgbuf_envs);

    int nenvs = 0, noverwrite = 0;
    for (const char ** e = envp ; *e ; e++, nenvs++)
        for (int i = 0 ; i < nsetenvs ; i++)
            if (!memcmp(setenvs[i].str, *e, setenvs[i].len) &&
                (*e)[setenvs[i].len] == '=') {
                setenvs[i].idx = nenvs;
                noverwrite++;
                break;
            }

    /* TODO: This code appears to rely on the memory buffer being zero-
     * initialized, so we use calloc here to get zeroed memory. We should
     * audit this code to verify that it's correct. */
    const char ** new_envp =
        calloc((nenvs + nsetenvs - noverwrite + 1), sizeof(const char *));
    memcpy(new_envp, envp, sizeof(const char *) * nenvs);
    envp = new_envp;

    char key[CONFIG_MAX] = "loader.env.";
    int prefix_len = static_strlen("loader.env.");
    const char ** ptr;
    char cfgbuf[CONFIG_MAX];

    for (int i = 0 ; i < nsetenvs ; i++) {
        const char * str = setenvs[i].str;
        int len = setenvs[i].len;
        int idx = setenvs[i].idx;
        ssize_t bytes;
        ptr = &envp[(idx == -1) ? nenvs++ : idx];
        memcpy(key + prefix_len, str, len + 1);
        if ((bytes = get_config(store, key, cfgbuf, sizeof(cfgbuf))) > 0) {
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
    ssize_t ret = 0;

    if (!pal_state.root_config)
        return;

    ret = get_config(pal_state.root_config, "loader.debug_type",
                     cfgbuf, sizeof(cfgbuf));
    if (ret <= 0)
        return;

    PAL_HANDLE handle = NULL;

    if (!strcmp_static(cfgbuf, "inline")) {
        ret = _DkStreamOpen(&handle, URI_PREFIX_DEV "tty", PAL_ACCESS_RDWR, 0, 0, 0);
    } else if (!strcmp_static(cfgbuf, "file")) {
        ret = get_config(pal_state.root_config, "loader.debug_file",
                         cfgbuf, sizeof(cfgbuf));
        if (ret <= 0)
            INIT_FAIL(PAL_ERROR_INVAL, "debug file not specified");

        ret = _DkStreamOpen(&handle, cfgbuf,
                            PAL_ACCESS_RDWR,
                            PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                            PAL_CREATE_TRY, 0);
    } else if (!strcmp_static(cfgbuf, "none")) {
        ret = 0;
    } else {
        INIT_FAIL(PAL_ERROR_INVAL, "unknown debug type");
    }

    if (ret < 0)
        INIT_FAIL(-ret, "cannot open debug stream");

    __pal_control.debug_stream = handle;
}

static int loader_filter (const char * key, int len)
{
    /* try to do this as fast as possible */
    return (len > 7 && key[0] == 'l' && key[1] == 'o' && key[2] == 'a' && key[3] == 'd' &&
            key[4] == 'e' && key[5] == 'r' && key[6] == '.') ? 0 : 1;
}

/* 'pal_main' must be called by the host-specific bootloader */
noreturn void pal_main (
        PAL_NUM    instance_id,      /* current instance id */
        PAL_HANDLE manifest_handle,  /* manifest handle if opened */
        PAL_HANDLE exec_handle,      /* executable handle if opened */
        PAL_PTR    exec_loaded_addr, /* executable addr if loaded */
        PAL_HANDLE parent_process,   /* parent process if it's a child */
        PAL_HANDLE first_thread,     /* first thread handle */
        PAL_STR *  arguments,        /* application arguments */
        PAL_STR *  environments      /* environment variables */
    )
{
#if PROFILING == 1
    __pal_control.host_specific_startup_time =
            _DkSystemTimeQuery() - pal_state.start_time;
#endif

    pal_state.instance_id = instance_id;
    pal_state.alloc_align = _DkGetAllocationAlignment();
    assert(IS_POWER_OF_2(pal_state.alloc_align));

    init_slab_mgr(pal_state.alloc_align);

    pal_state.parent_process = parent_process;

    char uri_buf[URI_MAX];
    char * manifest_uri = NULL, * exec_uri = NULL;
    ssize_t ret;

    if (exec_handle) {
        ret = _DkStreamGetName(exec_handle, uri_buf, URI_MAX);
        if (ret < 0)
            INIT_FAIL(-ret, "cannot get executable name");

        exec_uri = malloc_copy(uri_buf, ret + 1);
    }

    if (manifest_handle) {
        ret = _DkStreamGetName(manifest_handle, uri_buf, URI_MAX);
        if (ret < 0)
            INIT_FAIL(-ret, "cannot get manifest name");

        manifest_uri = malloc_copy(uri_buf, ret + 1);
    } else {
        if (!exec_handle)
            INIT_FAIL(PAL_ERROR_INVAL, "Must have manifest or executable");

#if PROFILING == 1
        unsigned long before_find_manifest = _DkSystemTimeQuery();
#endif

        /* try open "<execname>.manifest" */
        size_t len = sizeof(uri_buf);
        ret = get_norm_path(exec_uri, uri_buf, &len);
        if (ret < 0) {
            INIT_FAIL(-ret, "cannot normalize exec_uri");
        }

        strcpy_static(uri_buf + len, ".manifest", sizeof(uri_buf) - len);
        ret = _DkStreamOpen(&manifest_handle, uri_buf, PAL_ACCESS_RDONLY, 0, 0, 0);
        if (ret) {
            /* try open "file:manifest" */
            manifest_uri = URI_PREFIX_FILE "manifest";
            ret = _DkStreamOpen(&manifest_handle, manifest_uri, PAL_ACCESS_RDONLY,
                                0, 0, 0);
            if (ret) {
#if PROFILING == 1
                pal_state.manifest_loading_time +=
                    _DkSystemTimeQuery() - before_find_manifest;
#endif

                /* well, there is no manifest file, leave it alone */
                printf("Can't find any manifest, will run without one.\n");
            }
        }
    }

    /* load manifest if there is one */
    if (!pal_state.root_config && manifest_handle) {
#if PROFILING == 1
        unsigned long before_load_manifest = _DkSystemTimeQuery();
#endif

        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQueryByHandle(manifest_handle, &attr);
        if (ret < 0)
            INIT_FAIL(-ret, "cannot open manifest file");

        void * cfg_addr = NULL;
        int cfg_size = attr.pending_size;

        ret = _DkStreamMap(manifest_handle, &cfg_addr,
                           PAL_PROT_READ, 0,
                           ALLOC_ALIGN_UP(cfg_size));
        if (ret < 0)
            INIT_FAIL(-ret, "cannot open manifest file");

        struct config_store * root_config = malloc(sizeof(struct config_store));
        root_config->raw_data = cfg_addr;
        root_config->raw_size = cfg_size;
        root_config->malloc = malloc;
        root_config->free = free;

        const char * errstring = NULL;
        if ((ret = read_config(root_config, loader_filter, &errstring)) < 0) {
            if (_DkStreamGetName(manifest_handle, uri_buf, URI_MAX) > 0)
                printf("reading manifest \"%s\" failed\n", uri_buf);
            INIT_FAIL(-ret, errstring);
        }

        pal_state.root_config = root_config;

#if PROFILING == 1
        pal_state.manifest_loading_time +=
                        _DkSystemTimeQuery() - before_load_manifest;
#endif
    }

    /* if there is no executable, try to find one in the manifest */
    if (!exec_handle && pal_state.root_config) {
        ret = get_config(pal_state.root_config, "loader.exec",
                         uri_buf, URI_MAX);
        if (ret > 0) {
            exec_uri = malloc_copy(uri_buf, ret + 1);
            ret = _DkStreamOpen(&exec_handle, exec_uri, PAL_ACCESS_RDONLY,
                                0, 0, 0);
            if (ret < 0)
                INIT_FAIL(-ret, "cannot open executable");
        }
    }

    /* If we still don't have an exec in the manifest, but we have a manifest
     * try implicitly from the manifest name */
    if ((!exec_handle) && manifest_uri) {
        size_t manifest_strlen = strlen(manifest_uri);
        size_t exec_strlen = manifest_strlen - 9;
        int success = 0;
        // Try .manifest
        if (!strcmp_static(&manifest_uri[exec_strlen], ".manifest")) {
            success = 1;
        } else {
            exec_strlen -= 4;
            if (!strcmp_static(&manifest_uri[exec_strlen], ".manifest.sgx")) {
                success = 1;
            }
        }

        if (success) {
            exec_uri = malloc(exec_strlen + 1);
            if (!exec_uri)
                INIT_FAIL(-PAL_ERROR_NOMEM, "Cannot allocate URI buf");
            memcpy (exec_uri, manifest_uri, exec_strlen);
            exec_uri[exec_strlen] = '\0';
            ret = _DkStreamOpen(&exec_handle, exec_uri, PAL_ACCESS_RDONLY,
                                0, 0, 0);
            // DEP 3/20/17: There are cases where we want to let
            // the PAL start up without a main executable.  Don't
            // die here, just free the exec_uri buffer.
            if (ret < 0) {
                free(exec_uri);
                exec_uri = NULL;
            }
        }
    }

    /* must be an ELF */
    if (exec_handle) {
        if (exec_loaded_addr) {
            if (check_elf_magic(exec_loaded_addr, sizeof(ElfW(Ehdr))))
                INIT_FAIL(PAL_ERROR_INVAL, "executable is not an ELF binary");
        } else {
            if (check_elf_object(exec_handle) < 0)
                INIT_FAIL(PAL_ERROR_INVAL, "executable is not an ELF binary");
        }
    }

    pal_state.manifest        = manifest_uri;
    pal_state.manifest_handle = manifest_handle;
    pal_state.exec            = exec_uri;
    pal_state.exec_handle     = exec_handle;

    if (pal_state.root_config && *arguments
        && (strendswith(*arguments, ".manifest") || strendswith(*arguments, ".manifest.sgx"))) {
        /* Run as a manifest file,
         * replace argv[0] with the contents of the manifest's loader.execname */
        char cfgbuf[CONFIG_MAX];
        ret = get_config(pal_state.root_config, "loader.execname", cfgbuf, sizeof(cfgbuf));
        if (ret > 0)
            *arguments = malloc_copy(cfgbuf, ret + 1);
    }

    read_environments(&environments);

    if (pal_state.root_config)
        load_libraries();

    if (exec_handle) {
#if PROFILING == 1
        unsigned long before_load_exec = _DkSystemTimeQuery();
#endif

        if (exec_loaded_addr) {
            ret = add_elf_object(exec_loaded_addr, exec_handle, OBJECT_EXEC);
        } else {
            ret = load_elf_object_by_handle(exec_handle, OBJECT_EXEC);
        }

        if (ret < 0)
            INIT_FAIL(ret, pal_strerror(ret));

#if PROFILING == 1
        pal_state.linking_time += _DkSystemTimeQuery() - before_load_exec;
#endif
    }

#if PROFILING == 1
    unsigned long before_tail = _DkSystemTimeQuery();
#endif

    set_debug_type();

    __pal_control.host_type          = XSTRINGIFY(HOST_TYPE);
    __pal_control.process_id         = _DkGetProcessId();
    __pal_control.host_id            = _DkGetHostId();
    __pal_control.manifest_handle    = manifest_handle;
    __pal_control.executable         = exec_uri;
    __pal_control.parent_process     = parent_process;
    __pal_control.first_thread       = first_thread;

    _DkGetAvailableUserAddressRange(&__pal_control.user_address.start,
                                    &__pal_control.user_address.end,
                                    &__pal_control.user_address_hole.start,
                                    &__pal_control.user_address_hole.end);

    __pal_control.alloc_align        = pal_state.alloc_align;

    if (_DkGetCPUInfo(&__pal_control.cpu_info) < 0) {
        goto out_fail;
    }
    __pal_control.mem_info.mem_total = _DkMemoryQuota();

#if PROFILING == 1
    pal_state.tail_startup_time      += _DkSystemTimeQuery() - before_tail;

    __pal_control.relocation_time     = pal_state.relocation_time;
    __pal_control.linking_time        = pal_state.linking_time;
    __pal_control.manifest_loading_time
                                      = pal_state.manifest_loading_time;
    __pal_control.allocation_time     = pal_state.slab_time;
    __pal_control.child_creation_time = (parent_process == NULL) ? 0 : pal_state.start_time -
                                        pal_state.process_create_time;
#endif

    /* Now we will start the execution */
    start_execution(arguments, environments);

 out_fail:
    /* We wish we will never reached here */
    INIT_FAIL(PAL_ERROR_DENIED, "unexpected termination");
}

void write_log (int nstrs, ...)
{
    const char ** strs = __alloca(sizeof(const char *) * nstrs);
    int len = 0;
    va_list ap;

    va_start(ap, nstrs);
    for (int i = 0 ; i < nstrs ; i++) {
        strs[i] = va_arg(ap, char *);
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
