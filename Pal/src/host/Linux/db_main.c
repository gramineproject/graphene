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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <asm/mman.h>
#include <asm/ioctls.h>
#include <fcntl.h>
#include <asm-errno.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>
#include <sys/types.h>

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
asm (".global pal_start \n"
     "  .type pal_start,@function \n"
     "pal_start: \n"
     "  movq %rsp, %rdi \n"
     "  call pal_linux_main \n");

#define RTLD_BOOTSTRAP

/* pal_start is the entry point of libpal.so, which calls pal_main */
#define _ENTRY pal_start

asm (".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\r\n"
     ".byte 1\r\n"
     ".asciz \"" XSTRINGIFY(GDB_SCRIPT) "\"\r\n"
     ".popsection\r\n");

struct pal_linux_config pal_linux_config;

static size_t pagesz = PRESET_PAGESIZE;
static uid_t uid;
static gid_t gid;
#if USE_VDSO_GETTIME == 1
static ElfW(Addr) sysinfo_ehdr;
#endif

static const char * child_args;

static void pal_init_bootstrap (void * args, int * pargc,
                                const char *** pargv,
                                const char *** penvp)
{
    /*
     * fetch arguments and environment variables, the previous stack
     * pointer is in rdi (arg). The stack structure starting at rdi
     * will look like:
     *            auxv[m - 1] = AT_NULL
     *            ...
     *            auxv[0]
     *            envp[n - 1] = NULL
     *            ...
     *            envp[0]
     *            argv[argc] = NULL
     *            argv[argc - 1]
     *            ...
     *            argv[0]
     *            argc
     *       ---------------------------------------
     *            user stack
     */
    const char ** all_args = (const char **) args;
    int argc = (uintptr_t) all_args[0];
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;

    /* fetch environment information from aux vectors */
    void ** auxv = (void **) envp + 1;
    for (; *(auxv - 1); auxv++);
    ElfW(auxv_t) *av;
    for (av = (ElfW(auxv_t) *)auxv ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_PAGESZ:
                pagesz = av->a_un.a_val;
                break;
            case AT_UID:
            case AT_EUID:
                uid ^= av->a_un.a_val;
                break;
            case AT_GID:
            case AT_EGID:
                gid ^= av->a_un.a_val;
                break;
#if USE_VDSO_GETTIME == 1
            case AT_SYSINFO_EHDR:
                sysinfo_ehdr = av->a_un.a_val;
                break;
#endif
        }

    if (!memcmp(*argv + strlen(*argv) - 3, "pal", 3)) {
        argv++;
        argc--;

        if (argc >= 1 && (*argv)[0] == ':') {
            child_args = (*argv) + 1;
            argv++;
            argc--;
        }
    }

    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
}

unsigned long _DkGetPagesize (void)
{
    return pagesz;
}

unsigned long _DkGetAllocationAlignment (void)
{
    return pagesz;
}

static PAL_HANDLE try_open_runnable (const char * name, bool try_path,
                                     const char ** uri)
{
    PAL_HANDLE handle = NULL;
    /* Try to open the manifest file specified by the first argument */
    if (_DkStreamOpen(&handle, name, PAL_ACCESS_RDONLY, 0, 0, 0) == 0) {
        if (uri)
            *uri = name;
        return handle;
    }

    if (!try_path)
        return NULL;

    /* might be a real path, let's try open it */
    int fd = INLINE_SYSCALL(open, 3, name, O_RDONLY|O_CLOEXEC, 0);

    if (IS_ERR(fd))
        return NULL;

    int len = strlen(name);
    handle = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(handle, file);
    handle->__in.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    handle->file.fd = fd;
    char * path = (void *) handle + HANDLE_SIZE(file);
    memcpy(path, name, len + 1);
    handle->file.realpath = path;

    if (uri) {
        char * new_uri = malloc(len + 6);
        memcpy(new_uri, "file:", 5);
        memcpy(new_uri + 5, name, len + 1);
        *uri = new_uri;
    }

    return handle;
}

int read_shebang (const char ** argv)
{
    /* must be a shebang */
    int fd = INLINE_SYSCALL(open, 3, *argv, O_RDONLY|O_CLOEXEC, 0);

    if (IS_ERR(fd)) {
bad_shebang:
        INLINE_SYSCALL(close, 1, fd);
        return -PAL_ERROR_INVAL;
    }

    /* the maximun length for shebang path is 80 chars */
    char buffer[80];
    int bytes = INLINE_SYSCALL(read, 3, fd, buffer, 80);
    if (IS_ERR(bytes))
        goto bad_shebang;

    /* the format of shebang should be '#!/absoulte/path/of/pal' */
    if (buffer[0] != '#' || buffer[1] != '!')
        goto bad_shebang;

    char * p = &buffer[2];
    while (*p && *p != ' ' && *p != '\r' && *p != '\n')
        p++;

    int len = strlen(*argv);
    PAL_HANDLE manifest = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(manifest, file);
    manifest->__in.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    manifest->file.fd = fd;
    char * path = (void *) manifest + HANDLE_SIZE(file);
    memcpy(path, *argv, len + 1);
    manifest->file.realpath = path;
    char * uri = malloc(len + 6);
    memcpy(uri, "file:", 5);
    memcpy(uri + 5, *argv, len + 1);
    pal_config.manifest = uri;
    pal_config.manifest_handle = manifest;

    return 0;
}

#include "elf-x86_64.h"
#include "dynamic_link.h"

extern void setup_pal_map (const char * realname, ElfW(Dyn) ** dyn,
                           ElfW(Addr) addr);

void pal_linux_main (void * args)
{
    int argc;
    const char ** argv, ** envp;

    /* parse argc, argv, envp and auxv */
    pal_init_bootstrap(args, &argc, &argv, &envp);

    ElfW(Addr) pal_addr = elf_machine_load_address();
    ElfW(Dyn) * pal_dyn[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                        DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    memset(pal_dyn, 0, sizeof(pal_dyn));
    elf_get_dynamic_info((void *) pal_addr + elf_machine_dynamic(), pal_dyn,
                         pal_addr);
    ELF_DYNAMIC_RELOCATE(pal_dyn, pal_addr);

    init_slab_mgr();

    setup_pal_map(XSTRINGIFY(SRCDIR) "/pal", pal_dyn, pal_addr);

    /* jump to main function */
    pal_main(argc, argv, envp);
}

int create_domain_dir (void)
{
    int ret = 0;
    const char * path;

    ret = INLINE_SYSCALL(mkdir, 2, (path = GRAPHENE_PIPEDIR), 0777);

    if (IS_ERR(ret) && ERRNO(ret) != EEXIST) {
        if (ERRNO(ret) == ENOENT) {
            ret = INLINE_SYSCALL(mkdir, 2, (path = GRAPHENE_TMPDIR), 0777);
            if (!IS_ERR(ret)) {
                INLINE_SYSCALL(chmod, 2, GRAPHENE_TMPDIR, 0777);
                ret = INLINE_SYSCALL(mkdir, 2, (path = GRAPHENE_PIPEDIR), 0777);
            }
        }

        if (IS_ERR(ret)) {
            printf("Cannot create directory %s (%e), "
                   "please check permission\n", path, ERRNO(ret));
            return -PAL_ERROR_DENIED;
        }
    }

    if (!IS_ERR(ret))
        INLINE_SYSCALL(chmod, 2, GRAPHENE_PIPEDIR, 0777);

    char * pipedir = __alloca(GRAPHENE_PIPEDIR_LEN + 10);
    unsigned int id;

    do {
        if (!getrand(&id, sizeof(unsigned int))) {
            printf("Unable to generate random numbers\n");
            return -PAL_ERROR_DENIED;
        }

        snprintf(pipedir, GRAPHENE_PIPEDIR_LEN + 10,
                 GRAPHENE_PIPEDIR "/%08x", id);

        ret = INLINE_SYSCALL(mkdir, 2, pipedir, 0700);

        if (IS_ERR(ret) && ERRNO(ret) != -EEXIST) {
            printf("Cannot create directory %s (%e), "
                   "please fix permission\n", pipedir, ERRNO(ret));
            return -PAL_ERROR_DENIED;
        }
    } while (IS_ERR(ret));

    pal_sec_info.domain_id = id;
    return 0;
}

int init_child_process (const char * proc_args);
int signal_setup (void);

#if USE_VDSO_GETTIME == 1
void setup_vdso_map (ElfW(Addr) addr);
#endif

static int loader_filter (const char * key, int len)
{
    return memcmp(key, "loader.", 7);
}

int _DkInitHost (int * pargc, const char *** pargv)
{
    int argc = *pargc;
    const char ** argv = *pargv, * first_argv = NULL;
    int ret = 0;

    if (!child_args && !argc) {
        printf("USAGE: libpal.so [executable|manifest] args ...\n");
        return -PAL_ERROR_INVAL;
    }

    pal_linux_config.pid = INLINE_SYSCALL(getpid, 0);

    signal_setup();

    if (child_args) {
        if ((ret = init_child_process(child_args)) < 0)
            return ret;

        goto read_manifest;
    }

    if (!(ret = read_shebang(argv)) < 0)
        goto read_manifest;

    PAL_HANDLE file = NULL;
    const char * file_uri = NULL;

    if (argv[0][0] != '-') {
        file = try_open_runnable(argv[0], true, &file_uri);
        if (!file)
            return -PAL_ERROR_DENIED;

        first_argv = argv[0];
        argc--;
        argv++;

        /* the file laoded might be a executable */
        if (check_elf_object(file)) {
            pal_config.manifest        = file_uri;
            pal_config.manifest_handle = file;
            goto read_manifest;
        }

        pal_config.exec        = file_uri;
        pal_config.exec_handle = file;

        const char * manifest_uri;
        char manifest_path[80];
        snprintf(manifest_path, 80, "%s.manifest", pal_config.exec);

        if ((file = try_open_runnable(manifest_path, false, &manifest_uri))) {
            pal_config.manifest = manifest_uri;
            pal_config.manifest_handle = file;
            goto read_manifest;
        }
    }

    if ((file = try_open_runnable("file:manifest", false, NULL))) {
        pal_config.manifest = "file:manifest";
        pal_config.manifest_handle = file;
        goto read_manifest;
    }

read_manifest:
    if (!pal_config.manifest_handle) {
        printf("Can't fine any manifest, going to run without one\n");
        goto done_init;
    }

    PAL_STREAM_ATTR attr;

    if ((ret = _DkStreamAttributesQuerybyHandle(pal_config.manifest_handle,
                                                &attr)) < 0)
        return ret;

    void * cfg_addr = NULL;
    size_t cfg_size = attr.size;

    if ((ret = _DkStreamMap(pal_config.manifest_handle, &cfg_addr,
                            PAL_PROT_READ, 0,
                            ALLOC_ALIGNUP(cfg_size))) < 0)
        return ret;

    struct config_store * root_config = malloc(sizeof(struct config_store));
    root_config->raw_data = cfg_addr;
    root_config->raw_size = cfg_size;
    root_config->malloc = malloc;
    root_config->free = free;

    const char * errstring = NULL;

    if ((ret = read_config(root_config, loader_filter, &errstring)) < 0) {
        printf("Can't read manifest: %s\n", errstring);
        return -PAL_ERROR_INVAL;
    }

    pal_config.root_config = root_config;

    char cfgbuf[CONFIG_MAX];
    int len;

    if (!pal_linux_config.noexec && !pal_config.exec_handle) {
        /* find executable in the manifest */
        if ((len = get_config(root_config, "loader.exec", cfgbuf,
                              CONFIG_MAX)) > 0) {
            if (!(file = try_open_runnable(cfgbuf, false, NULL)))
                return -PAL_ERROR_DENIED;

            if ((ret = check_elf_object(file)) < 0)
                return ret;

            pal_config.exec = remalloc(cfgbuf, len + 1);
            pal_config.exec_handle = file;
        }
    }

    if (!child_args) {
        if ((len = get_config(root_config, "loader.execname", cfgbuf,
                              CONFIG_MAX)) > 0)
            first_argv = remalloc(cfgbuf, len + 1);

        if (!first_argv)
            first_argv = pal_config.exec;
    }

done_init:
    if (!child_args && !pal_sec_info.domain_id) {
        if ((ret = create_domain_dir()) < 0)
            return ret;
    }

    PAL_HANDLE thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(thread, thread);
    thread->thread.tid = pal_linux_config.pid;
    __pal_control.first_thread = thread;

#if USE_VDSO_GETTIME == 1
    if (sysinfo_ehdr)
        setup_vdso_map(sysinfo_ehdr);
#endif

    if (!pal_sec_info.mcast_port) {
        unsigned short mcast_port;
        getrand(&mcast_port, sizeof(unsigned short));
        pal_sec_info.mcast_port = mcast_port % 1024;
    }

    __pal_control.broadcast_stream = pal_sec_info.mcast_handle ? :
                            _DkBroadcastStreamOpen(pal_sec_info.mcast_port);

    if (first_argv) {
        argc++;
        argv--;
        argv[0] = first_argv;
    }

    *pargc = argc;
    *pargv = argv;

    return 0;
}
