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
        char* exec_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, argv[3], -1);
        if (!exec_uri)
            INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
        PAL_HANDLE file;
        int ret = _DkStreamOpen(&file, exec_uri, PAL_ACCESS_RDONLY, 0, 0, PAL_OPTION_CLOEXEC);
        free(exec_uri);
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

/* Opens a pseudo-file describing HW resources such as online CPUs and counts the number of
 * HW resources present in the file (if count == true) or simply reads the integer stored in the
 * file (if count == false). For example on a single-core machine, calling this function on
 * `/sys/devices/system/cpu/online` with count == true will return 1 and 0 with count == false.
 * Returns PAL error code on failure.
 * N.B: Understands complex formats like "1,3-5,6" when called with count == true.
 */
int get_hw_resource(const char* filename, bool count) {
    int fd = INLINE_SYSCALL(open, 3, filename, O_RDONLY | O_CLOEXEC, 0);
    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    char buf[64];
    int ret = INLINE_SYSCALL(read, 3, fd, buf, sizeof(buf) - 1);
    INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    buf[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* end;
    char* ptr = buf;
    int resource_cnt = 0;
    int retval = -PAL_ERROR_STREAMNOTEXIST;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        int firstint = (int)strtol(ptr, &end, 10);
        if (ptr == end)
            break;

        /* caller wants to read an int stored in the file */
        if (!count) {
            if (*end == '\n' || *end == '\0')
                retval = firstint;
            return retval;
        }

        /* caller wants to count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n') {
            /* single HW resource index, count as one more */
            resource_cnt++;
        } else if (*end == '-') {
            /* HW resource range, count how many HW resources are in range */
            ptr = end + 1;
            int secondint = (int)strtol(ptr, &end, 10);
            if (secondint > firstint)
                resource_cnt += secondint - firstint + 1; // inclusive (e.g., 0-7, or 8-16)
        }
        ptr = end;
    }

    if (count && resource_cnt > 0)
        retval = resource_cnt;

    return retval;
}

ssize_t read_file_buffer(const char* filename, char* buf, size_t buf_size) {
    int fd;

    fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY);
    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    ssize_t n = INLINE_SYSCALL(read, 3, fd, buf, buf_size);
    INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(n))
        return unix_to_pal_error(ERRNO(n));

    return n;
}

int get_num_cache_level(const char* path) {
    char buf[1024];
    int bpos;
    int nread;
    int num_dirs = 0;
    struct linux_dirent64* dirent64;

    int fd = INLINE_SYSCALL(open, 2, path, O_RDONLY | O_DIRECTORY);
    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    while (1) {
        nread = INLINE_SYSCALL(getdents64, 3, fd, buf, 1024);
        if (IS_ERR(nread))
            return unix_to_pal_error(ERRNO(nread));

        if (nread == 0)
            break;

        for (bpos = 0; bpos < nread;) {
            dirent64 = (struct linux_dirent64*)(buf + bpos);
            if (dirent64->d_type == DT_DIR && strncmp (dirent64->d_name, "index", 5) == 0)
                num_dirs++;
            bpos += dirent64->d_reclen;
        }
    }

    INLINE_SYSCALL(close, 1, fd);
    if (num_dirs)
        return num_dirs;

    return -PAL_ERROR_STREAMNOTEXIST;;
}

/*Get Core topology related info*/
int get_core_topo_info(PAL_TOPO_INFO* topo_info) {
    int num_online_logical_cores = get_hw_resource("/sys/devices/system/cpu/online",
                                                   /*count=*/true);
    if (num_online_logical_cores < 0)
        return num_online_logical_cores;

    int ret = read_file_buffer("/sys/devices/system/cpu/online", topo_info->online_logical_cores,
                               PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->online_logical_cores[ret] = '\0';

    ret = read_file_buffer("/sys/devices/system/cpu/possible", topo_info->possible_logical_cores,
                           PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->possible_logical_cores[ret] = '\0';

    int num_cache_lvl = get_num_cache_level("/sys/devices/system/cpu/cpu0/cache");
    if (num_cache_lvl < 0)
        return num_cache_lvl;
    topo_info->num_cache_index = num_cache_lvl;
    PAL_CORE_CACHE_INFO* core_cache;

    PAL_CORE_TOPO_INFO* core_topology = (PAL_CORE_TOPO_INFO*)malloc(num_online_logical_cores *
                                                                    sizeof(PAL_CORE_TOPO_INFO));
    if (!core_topology)
        return -PAL_ERROR_NOMEM;

    char filename[128];
    for (int idx = 0; idx < num_online_logical_cores; idx++) {
        /* cpu0 is always online and so this file is not present */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", idx);
            ret = read_file_buffer(filename, core_topology[idx].is_logical_core_online,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_topology;
            core_topology[idx].is_logical_core_online[ret] = '\0';
        }

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/topology/core_id", idx);
        ret = read_file_buffer(filename, core_topology[idx].core_id, PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].core_id[ret] = '\0';

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/core_siblings", idx);
        ret = read_file_buffer(filename, core_topology[idx].core_siblings, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].core_siblings[ret] = '\0';

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings", idx);
        ret = read_file_buffer(filename, core_topology[idx].thread_siblings, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].thread_siblings[ret] = '\0';

        core_cache = (PAL_CORE_CACHE_INFO*)malloc(num_cache_lvl * sizeof(PAL_CORE_CACHE_INFO));
        if (!core_cache) {
            ret = -PAL_ERROR_NOMEM;
            goto out_topology;
        }

        for (int lvl = 0; lvl < num_cache_lvl; lvl++) {
            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_map", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].shared_cpu_map, PAL_SYSFS_MAP_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].shared_cpu_map[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/level", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].level, PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].level[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/type", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].type, PAL_SYSFS_BUF_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].type[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/size", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].size, PAL_SYSFS_BUF_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].size[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/coherency_line_size", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].coherency_line_size,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].coherency_line_size[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].number_of_sets, PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].number_of_sets[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/physical_line_partition", idx,
                     lvl);
            ret = read_file_buffer(filename, core_cache[lvl].physical_line_partition,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].physical_line_partition[ret] = '\0';
        }
        core_topology[idx].cache = core_cache;
    }
    topo_info->core_topology = core_topology;
    return 0;

out_cache:
    free(core_cache);
out_topology:
    free(core_topology);
    return ret;
}

/*Get Numa topology related info*/
int get_numa_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret = read_file_buffer("/sys/devices/system/node/online", topo_info->online_nodes,
                               PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->online_nodes[ret] = '\0';

    int num_nodes = get_hw_resource("/sys/devices/system/node/online", /*count=*/true);
    if (num_nodes < 0)
        return num_nodes;
    topo_info->num_online_nodes = num_nodes;

    PAL_NUMA_TOPO_INFO* numa_topology = (PAL_NUMA_TOPO_INFO*)malloc(num_nodes *
                                                                    sizeof(PAL_NUMA_TOPO_INFO));
    if (!numa_topology)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < num_nodes; idx++) {
        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/cpumap", idx);
        ret = read_file_buffer(filename, numa_topology[idx].cpumap, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].cpumap[ret] = '\0';

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/distance", idx);
        ret = read_file_buffer(filename, numa_topology[idx].distance, PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].distance[ret] = '\0';

        /* Collect hugepages info*/
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages", idx);
        ret = read_file_buffer(filename, numa_topology[idx].hugepages[HUGEPAGES_2M].nr_hugepages,
                               PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].hugepages[HUGEPAGES_2M].nr_hugepages[ret] = '\0';

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/node/node%d/hugepages/hugepages-1048576kB/nr_hugepages", idx);
        ret = read_file_buffer(filename, numa_topology[idx].hugepages[HUGEPAGES_1G].nr_hugepages,
                               PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].hugepages[HUGEPAGES_1G].nr_hugepages[ret] = '\0';

    }
    topo_info->numa_topology = numa_topology;
    return 0;

out_topology:
    free(numa_topology);
    return ret;
}
