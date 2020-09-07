/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
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

/* use objfile-gdb convention instead of .debug_gdb_scripts */
#ifdef DEBUG
__asm__(
    ".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\r\n"
    ".byte 1\r\n"
    ".asciz \"pal-gdb.py\"\r\n"
    ".popsection\r\n");
#endif

char* g_pal_loader_path = NULL;
/* Currently content of this variable is only passed as an argument while spawning new processes
 * - this is to keep uniformity with other PALs. */
char* g_libpal_path = NULL;

struct pal_linux_state g_linux_state;
struct pal_sec g_pal_sec;

static size_t g_page_size = PRESET_PAGESIZE;
static int g_uid, g_gid;
#if USE_VDSO_GETTIME == 1
static ElfW(Addr) g_sysinfo_ehdr;
#endif

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
        if (!strcmp_static(*e, "IN_GDB=1"))
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
#if USE_VDSO_GETTIME == 1
            case AT_SYSINFO_EHDR:
                g_sysinfo_ehdr = av->a_un.a_val;
                break;
#endif
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
    void* start_addr = (void*)USER_ADDRESS_LOWEST;

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

PAL_NUM _DkGetHostId(void) {
    return 0;
}

#include "dynamic_link.h"

#if USE_VDSO_GETTIME == 1
void setup_vdso_map(ElfW(Addr) addr);
#endif

static struct link_map g_pal_map;

#include "elf-arch.h"

noreturn static void print_usage_and_exit(const char* argv_0) {
    const char* self = argv_0 ?: "<this program>";
    printf("USAGE:\n"
           "\tFirst process: %s <path to libpal.so> init [<executable>|<manifest>] args...\n"
           "\tChildren:      %s <path to libpal.so> child <parent_pipe_fd> args...\n",
           self, self);
    printf("This is an internal interface. Use pal_loader to launch applications in Graphene.\n");
    _DkProcessExit(1);
}

noreturn void pal_linux_main(void* initial_rsp, void* fini_callback) {
    __UNUSED(fini_callback);  // TODO: We should call `fini_callback` at the end.

    uint64_t start_time = _DkSystemTimeQueryEarly();
    g_pal_state.start_time = start_time;

    int ret;
    int argc;
    const char** argv;
    const char** envp;
    read_args_from_stack(initial_rsp, &argc, &argv, &envp);

    if (argc < 4)
        print_usage_and_exit(argv[0]);  // may be NULL!

    // Are we the first in this Graphene's namespace?
    bool first_process = !strcmp_static(argv[2], "init");
    if (!first_process && strcmp_static(argv[2], "child")) {
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
    tcb->common.self = &tcb->common;
    tcb->handle      = first_thread;
    tcb->alt_stack   = alt_stack; // Stack bottom
    tcb->callback    = NULL;
    tcb->param       = NULL;

    ret = pal_thread_init(tcb);
    if (ret < 0)
        INIT_FAIL(unix_to_pal_error(-ret), "pal_thread_init() failed");

    setup_pal_map(&g_pal_map);

#if USE_VDSO_GETTIME == 1
    if (g_sysinfo_ehdr)
        setup_vdso_map(g_sysinfo_ehdr);
#endif

    PAL_HANDLE parent = NULL, exec = NULL, manifest = NULL;
    if (!first_process) {
        // Children receive their argv and config via IPC.
        int parent_pipe_fd = atoi(argv[3]);
        init_child_process(parent_pipe_fd, &parent, &exec, &manifest);
    }

    if (!g_pal_sec.process_id)
        g_pal_sec.process_id = INLINE_SYSCALL(getpid, 0);
    g_linux_state.pid = g_pal_sec.process_id;

    g_linux_state.uid = g_uid;
    g_linux_state.gid = g_gid;
    g_linux_state.process_id = (start_time & (~0xffff)) | g_linux_state.pid;

    if (!g_linux_state.parent_process_id)
        g_linux_state.parent_process_id = g_linux_state.process_id;

    if (first_process) {
        // We need to find a binary to run.
        const char* exec_target = argv[3];
        size_t size = URI_PREFIX_FILE_LEN + strlen(exec_target) + 1;
        char* uri = malloc(size);
        if (!uri)
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
        snprintf(uri, size, URI_PREFIX_FILE "%s", exec_target);
        PAL_HANDLE file;
        int ret = _DkStreamOpen(&file, uri, PAL_ACCESS_RDONLY, 0, 0, PAL_OPTION_CLOEXEC);
        free(uri);
        if (ret < 0)
            INIT_FAIL(-ret, "Failed to open file to execute");

        if (is_elf_object(file)) {
            exec = file;
        } else {
            manifest = file;
        }
    }

    signal_setup();

    /* call to main function */
    pal_main((PAL_NUM)g_linux_state.parent_process_id, manifest, exec, NULL, parent, first_thread,
             first_process ? argv + 3 : argv + 4, envp);
}

/*
 * Returns the number of online CPUs read from /sys/devices/system/cpu/online, -errno on failure.
 * Understands complex formats like "1,3-5,6".
 */
int get_cpu_count(void) {
    int fd = INLINE_SYSCALL(open, 3, "/sys/devices/system/cpu/online", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return unix_to_pal_error(ERRNO(fd));

    char buf[64];
    int ret = INLINE_SYSCALL(read, 3, fd, buf, sizeof(buf) - 1);
    INLINE_SYSCALL(close, 1, fd);
    if (ret < 0) {
        return unix_to_pal_error(ERRNO(ret));
    }

    buf[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* end;
    char* ptr = buf;
    int cpu_count = 0;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        int firstint = (int)strtol(ptr, &end, 10);
        if (ptr == end)
            break;

        if (*end == '\0' || *end == ',' || *end == '\n') {
            /* single CPU index, count as one more CPU */
            cpu_count++;
        } else if (*end == '-') {
            /* CPU range, count how many CPUs in range */
            ptr = end + 1;
            int secondint = (int)strtol(ptr, &end, 10);
            if (secondint > firstint)
                cpu_count += secondint - firstint + 1; // inclusive (e.g., 0-7, or 8-16)
        }
        ptr = end;
    }

    if (cpu_count == 0)
        return -PAL_ERROR_STREAMNOTEXIST;
    return cpu_count;
}

ssize_t read_file_buffer(const char* filename, char* buf, size_t buf_size) {
    int fd;

    fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY);
    if (fd < 0)
        return fd;

    ssize_t n = INLINE_SYSCALL(read, 3, fd, buf, buf_size);
    INLINE_SYSCALL(close, 1, fd);

    return n;
}
