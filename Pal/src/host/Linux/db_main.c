/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>

#include "api.h"
#include "elf/elf.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "sysdeps/generic/ldsodefs.h"

#define RTLD_BOOTSTRAP

/* pal_start is the entry point of libpal.so, which calls pal_main */
#define _ENTRY pal_start

char* g_pal_loader_path = NULL;
/* Currently content of this variable is only passed as an argument while spawning new processes
 * - this is to keep uniformity with other PALs. */
char* g_libpal_path = NULL;

struct pal_linux_state g_linux_state;
struct pal_sec g_pal_sec;

static size_t g_page_size = PRESET_PAGESIZE;
static int g_uid, g_gid;
static ElfW(Addr) g_sysinfo_ehdr;

static void read_args_from_stack(void* initial_rsp, int* out_argc, const char*** out_argv,
                                 const char*** out_envp) {
    /* The stack layout on program entry is:
     *
     *            argc                  <-- `initial_rsp` points here
     *            argv[0]
     *            ...
     *            argv[argc - 1]
     *            argv[argc] = NULL
     *            envp[0]
     *            ...
     *            envp[n - 1] = NULL
     *            auxv[0]
     *            ...
     *            auxv[m - 1] = AT_NULL
     */
    const char** stack = (const char**)initial_rsp;
    int argc = (uintptr_t)stack[0];
    const char** argv = &stack[1];
    const char** envp = argv + argc + 1;
    assert(argv[argc] == NULL);

    const char** e = envp;
    for (; *e; e++) {
#ifdef DEBUG
        if (!strcmp(*e, "IN_GDB=1"))
            g_linux_state.in_gdb = true;
#endif
    }

    for (ElfW(auxv_t)* av = (ElfW(auxv_t)*)(e + 1); av->a_type != AT_NULL; av++) {
        switch (av->a_type) {
            case AT_PAGESZ:
                g_page_size = av->a_un.a_val;
                break;
            case AT_UID:
            case AT_EUID:
                g_uid ^= av->a_un.a_val;
                break;
            case AT_GID:
            case AT_EGID:
                g_gid ^= av->a_un.a_val;
                break;
            case AT_SYSINFO_EHDR:
                g_sysinfo_ehdr = av->a_un.a_val;
                break;
        }
    }
    *out_argc = argc;
    *out_argv = argv;
    *out_envp = envp;
}

unsigned long _DkGetAllocationAlignment(void) {
    return g_page_size;
}

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    void* end_addr = (void*)ALLOC_ALIGN_DOWN_PTR(TEXT_START);
    void* start_addr = (void*)MMAP_MIN_ADDR;

    assert(IS_ALLOC_ALIGNED_PTR(start_addr) && IS_ALLOC_ALIGNED_PTR(end_addr));

    while (1) {
        if (start_addr >= end_addr)
            INIT_FAIL(PAL_ERROR_NOMEM, "no user memory available");

        void* mem = (void*)ARCH_MMAP(start_addr, g_pal_state.alloc_align, PROT_NONE,
                                     MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (!IS_ERR_P(mem)) {
            INLINE_SYSCALL(munmap, 2, mem, g_pal_state.alloc_align);
            if (mem == start_addr)
                break;
        }

        start_addr = (void*)((unsigned long)start_addr << 1);
    }

    *end   = (PAL_PTR)end_addr;
    *start = (PAL_PTR)start_addr;
}

PAL_NUM _DkGetProcessId(void) {
    return g_linux_state.process_id;
}

#include "dynamic_link.h"

static struct link_map g_pal_map;

#include "elf-arch.h"

noreturn static void print_usage_and_exit(const char* argv_0) {
    const char* self = argv_0 ?: "<this program>";
    printf("USAGE:\n"
           "\tFirst process: %s <path to libpal.so> init <application> args...\n"
           "\tChildren:      %s <path to libpal.so> child <parent_pipe_fd> args...\n",
           self, self);
    printf("This is an internal interface. Use pal_loader to launch applications in Graphene.\n");
    _DkProcessExit(1);
}

/* Graphene uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with no TCB in the GS register, so we disable stack protector here */
__attribute__((__optimize__("-fno-stack-protector")))
noreturn void pal_linux_main(void* initial_rsp, void* fini_callback) {
    __UNUSED(fini_callback);  // TODO: We should call `fini_callback` at the end.
    int ret;

    /* we don't yet have a TCB in the GS register, but GCC's stack protector will look for a canary
     * at gs:[0x8] in functions called below, so let's install a dummy TCB with a default canary */
    PAL_TCB_LINUX dummy_tcb_for_stack_protector = { 0 };
    dummy_tcb_for_stack_protector.common.self = &dummy_tcb_for_stack_protector.common;
    pal_tcb_set_stack_canary(&dummy_tcb_for_stack_protector.common, STACK_PROTECTOR_CANARY_DEFAULT);
    ret = pal_set_tcb(&dummy_tcb_for_stack_protector.common);
    if (ret < 0)
        INIT_FAIL(unix_to_pal_error(-ret), "pal_set_tcb() failed");

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0)
        INIT_FAIL(unix_to_pal_error(-ret), "_DkSystemTimeQuery() failed");

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_state.alloc_align = _DkGetAllocationAlignment();
    assert(IS_POWER_OF_2(g_pal_state.alloc_align));

    int argc;
    const char** argv;
    const char** envp;
    read_args_from_stack(initial_rsp, &argc, &argv, &envp);

    if (argc < 4)
        print_usage_and_exit(argv[0]);  // may be NULL!

    // Are we the first in this Graphene's namespace?
    bool first_process = !strcmp(argv[2], "init");
    if (!first_process && strcmp(argv[2], "child")) {
        print_usage_and_exit(argv[0]);
    }

    g_pal_map.l_addr = elf_machine_load_address();
    g_pal_map.l_name = argv[0];
    elf_get_dynamic_info((void*)g_pal_map.l_addr + elf_machine_dynamic(), g_pal_map.l_info,
                         g_pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&g_pal_map);

    g_linux_state.host_environ = envp;

    init_slab_mgr(g_page_size);

    g_pal_loader_path = get_main_exec_path();
    g_libpal_path = strdup(argv[1]);
    if (!g_pal_loader_path || !g_libpal_path) {
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    }

    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    if (!first_thread)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tid = INLINE_SYSCALL(gettid, 0);

    void* alt_stack = calloc(1, ALT_STACK_SIZE);
    if (!alt_stack)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    first_thread->thread.stack = alt_stack;

    // Initialize TCB at the top of the alternative stack.
    PAL_TCB_LINUX* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX);
    pal_tcb_linux_init(tcb, first_thread, alt_stack, /*callback=*/NULL, /*param=*/NULL);
    ret = pal_thread_init(tcb);
    if (ret < 0)
        INIT_FAIL(unix_to_pal_error(-ret), "pal_thread_init() failed");

    setup_pal_map(&g_pal_map);

    if (g_sysinfo_ehdr)
        setup_vdso_map(g_sysinfo_ehdr);

    if (!g_pal_sec.process_id)
        g_pal_sec.process_id = INLINE_SYSCALL(getpid, 0);
    g_linux_state.pid = g_pal_sec.process_id;

    g_linux_state.uid = g_uid;
    g_linux_state.gid = g_gid;
    g_linux_state.process_id = g_linux_state.pid;

    if (!g_linux_state.parent_process_id)
        g_linux_state.parent_process_id = g_linux_state.process_id;

    PAL_HANDLE parent = NULL;
    char* manifest = NULL;
    char* exec_uri = NULL; // TODO: This should be removed from here and handled by LibOS.
    if (first_process) {
        const char* application_path = argv[3];
        char* manifest_path = alloc_concat(application_path, -1, ".manifest", -1);
        if (!manifest_path)
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");

        ret = read_text_file_to_cstr(manifest_path, &manifest);
        if (ret < 0) {
            INIT_FAIL(-ret, "Reading manifest failed");
        }
    } else {
        // Children receive their argv and config via IPC.
        int parent_pipe_fd = atoi(argv[3]);
        init_child_process(parent_pipe_fd, &parent, &exec_uri, &manifest);
        assert(exec_uri);
    }
    assert(manifest);

    signal_setup();

    g_pal_state.raw_manifest_data = manifest;

    char errbuf[256];
    g_pal_state.manifest_root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!g_pal_state.manifest_root)
        INIT_FAIL_MANIFEST(PAL_ERROR_DENIED, errbuf);

    if (!exec_uri) {
        ret = toml_string_in(g_pal_state.manifest_root, "libos.entrypoint", &exec_uri);
        if (ret < 0) {
            INIT_FAIL_MANIFEST(PAL_ERROR_INVAL, "Cannot parse 'libos.entrypoint'\n");
        } else if (exec_uri == NULL) {
            // Temporary hack for PAL regression tests. TODO: We should always error out here.
            char* pal_entrypoint;
            ret = toml_string_in(g_pal_state.manifest_root, "pal.entrypoint", &pal_entrypoint);
            if (ret < 0)
                INIT_FAIL(PAL_ERROR_INVAL, "Cannot parse 'pal.entrypoint'\n");
            if (!pal_entrypoint)
                INIT_FAIL(PAL_ERROR_INVAL,
                          "'libos.entrypoint' must be specified in the manifest\n");
        }
    }

    /* call to main function */
    pal_main((PAL_NUM)g_linux_state.parent_process_id, exec_uri, parent, first_thread,
             first_process ? argv + 3 : argv + 4, envp);
}
