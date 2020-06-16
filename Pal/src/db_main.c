/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
 */

#include <stdbool.h>

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
                *c = 0;
                if ((ret = load_elf_object(library_name, OBJECT_PRELOAD)) < 0)
                    INIT_FAIL(-ret, "Unable to load preload library");
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
noreturn void pal_main(
        PAL_NUM    instance_id,      /* current instance id */
        PAL_HANDLE manifest_handle,  /* manifest handle if opened */
        PAL_HANDLE exec_handle,      /* executable handle if opened */
        PAL_PTR    exec_loaded_addr, /* executable addr if loaded */
        PAL_HANDLE parent_process,   /* parent process if it's a child */
        PAL_HANDLE first_thread,     /* first thread handle */
        PAL_STR*   arguments,        /* application arguments */
        PAL_STR*   environments      /* environment variables */) {
    char cfgbuf[CONFIG_MAX];
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
                INIT_FAIL(PAL_ERROR_DENIED, "cannot find manifest file");
            }
        }
    }

    /* load manifest if there is one */
    if (!pal_state.root_config && manifest_handle) {
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
                INIT_FAIL(PAL_ERROR_NOMEM, "Cannot allocate URI buf");
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
            if (!has_elf_magic(exec_loaded_addr, sizeof(ElfW(Ehdr))))
                INIT_FAIL(PAL_ERROR_INVAL, "executable is not an ELF binary");
        } else {
            if (!is_elf_object(exec_handle))
                INIT_FAIL(PAL_ERROR_INVAL, "executable is not an ELF binary");
        }
    }

    pal_state.manifest        = manifest_uri;
    pal_state.manifest_handle = manifest_handle;
    pal_state.exec            = exec_uri;
    pal_state.exec_handle     = exec_handle;

    bool disable_aslr = false;
    if (pal_state.root_config) {
        char aslr_cfg[2];
        ssize_t len = get_config(pal_state.root_config, "loader.insecure__disable_aslr", aslr_cfg,
                                 sizeof(aslr_cfg));
        disable_aslr = len == 1 && aslr_cfg[0] == '1';
    }

    /* Load argv */
    /* TODO: Add an option to specify argv inline in the manifest. This requires an upgrade to the
     * manifest syntax. See https://github.com/oscarlab/graphene/issues/870 (Use YAML or TOML syntax
     * for manifests). 'loader.argv0_override' won't be needed after implementing this feature and
     * resolving https://github.com/oscarlab/graphene/issues/1053 (RFC: graphene invocation).
     */
    bool argv0_overridden = false;
    if (pal_state.root_config) {
        ret = get_config(pal_state.root_config, "loader.argv0_override", cfgbuf, sizeof(cfgbuf));
        if (ret > 0) {
            argv0_overridden = true;
            if (!arguments[0]) {
                arguments = malloc(sizeof(const char*) * 2);
                if (!arguments)
                    INIT_FAIL(PAL_ERROR_NOMEM, "malloc() failed");
                arguments[1] = NULL;
            }
            arguments[0] = malloc_copy(cfgbuf, ret + 1);
            if (!arguments[0])
                INIT_FAIL(PAL_ERROR_NOMEM, "malloc() failed");
        }
    }

    if (get_config(pal_state.root_config, "loader.insecure__use_cmdline_argv",
                   cfgbuf, CONFIG_MAX) > 0) {
        printf("WARNING: Using insecure argv source. Don't use this configuration in production!\n");
    } else if (get_config(pal_state.root_config, "loader.argv_src_file", cfgbuf, CONFIG_MAX) > 0) {
        /* Load argv from a file and discard cmdline argv. We trust the file contents (this can be
         * achieved using protected or trusted files). */
        if (arguments[0] && arguments[1])
            printf("Discarding cmdline arguments (%s %s [...]) because loader.argv_src_file was "
                   "specified in the manifest.\n", arguments[0], arguments[1]);

        PAL_HANDLE argv_handle;
        PAL_STREAM_ATTR attr;
        ret = _DkStreamOpen(&argv_handle, cfgbuf, PAL_ACCESS_RDONLY, 0, 0, 0);
        if (ret < 0)
            INIT_FAIL(-ret, "can't open loader.argv_src_file");
        ret = _DkStreamAttributesQueryByHandle(argv_handle, &attr);
        if (ret < 0)
            INIT_FAIL(-ret, "can't read attributes of loader.argv_src_file");
        size_t argv_file_size = attr.pending_size;
        char* buf = malloc(argv_file_size);
        if (!buf)
            INIT_FAIL(PAL_ERROR_NOMEM, "malloc failed");
        ret = _DkStreamRead(argv_handle, 0, argv_file_size, buf, NULL, 0);
        if (ret < 0)
            INIT_FAIL(-ret, "can't read loader.argv_src_file");
        if (argv_file_size == 0 || buf[argv_file_size - 1] != '\0')
            INIT_FAIL(PAL_ERROR_INVAL, "loader.argv_src_file should contain a "
                                       "list of C-strings");
        ret = _DkObjectClose(argv_handle);
        if (ret < 0)
            INIT_FAIL(-ret, "closing loader.argv_src_file failed");

        /* Create argv array from the file contents. */
        size_t argc = 0;
        for (size_t i = 0; i < argv_file_size; i++)
            if (buf[i] == '\0')
                argc++;
        const char** argv = malloc(sizeof(const char*) * (argc + 1));
        if (!argv)
            INIT_FAIL(PAL_ERROR_NOMEM, "malloc() failed");
        assert(argc > 0);
        argv[argc] = NULL;
        const char** argv_it = argv;
        *(argv_it++) = buf;
        assert(argv_file_size > 0);
        for (size_t i = 0; i < argv_file_size - 1; i++)
            if (buf[i] == '\0')
                *(argv_it++) = buf + i + 1;
        arguments = argv;
    } else if (!argv0_overridden || (arguments[0] && arguments[1])) {
        INIT_FAIL(PAL_ERROR_INVAL, "argv handling wasn't configured in the manifest, but cmdline "
                  "arguments were specified.");
    }

    read_environments(&environments);

    if (pal_state.root_config)
        load_libraries();

    if (exec_handle) {
        if (exec_loaded_addr) {
            ret = add_elf_object(exec_loaded_addr, exec_handle, OBJECT_EXEC);
        } else {
            ret = load_elf_object_by_handle(exec_handle, OBJECT_EXEC);
        }

        if (ret < 0)
            INIT_FAIL(-ret, pal_strerror(ret));
    }

    set_debug_type();

    __pal_control.host_type          = XSTRINGIFY(HOST_TYPE);
    __pal_control.process_id         = _DkGetProcessId();
    __pal_control.host_id            = _DkGetHostId();
    __pal_control.manifest_handle    = manifest_handle;
    __pal_control.executable         = exec_uri;
    __pal_control.parent_process     = parent_process;
    __pal_control.first_thread       = first_thread;
    __pal_control.disable_aslr       = disable_aslr;

    _DkGetAvailableUserAddressRange(&__pal_control.user_address.start,
                                    &__pal_control.user_address.end,
                                    &__pal_control.exec_memory_gap);

    __pal_control.alloc_align        = pal_state.alloc_align;

    if (_DkGetCPUInfo(&__pal_control.cpu_info) < 0) {
        goto out_fail;
    }
    __pal_control.mem_info.mem_total = _DkMemoryQuota();

    /* Now we will start the execution */
    start_execution(arguments, environments);

 out_fail:
    /* We wish we will never reached here */
    INIT_FAIL(PAL_ERROR_DENIED, "unexpected termination");
}
