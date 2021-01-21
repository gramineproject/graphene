/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "api.h"
#include "ecall_types.h"
#include "elf/elf.h"
#include "enclave_pages.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "protected_files.h"
#include "sysdeps/generic/ldsodefs.h"
#include "toml.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_linux_state g_linux_state;
struct pal_sec g_pal_sec;

PAL_SESSION_KEY g_master_key = {0};

/* for internal PAL objects, Graphene first uses pre-allocated g_mem_pool and then falls back to
 * _DkVirtualMemoryAlloc(PAL_ALLOC_INTERNAL); the amount of available PAL internal memory is
 * limited by the variable below */
size_t g_pal_internal_mem_size = 0;

size_t g_page_size = PRESET_PAGESIZE;

unsigned long _DkGetAllocationAlignment(void) {
    return g_page_size;
}

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    *start = (PAL_PTR)g_pal_sec.heap_min;
    *end   = (PAL_PTR)get_enclave_heap_top();

    /* Keep some heap for internal PAL objects allocated at runtime (recall that LibOS does not keep
     * track of PAL memory, so without this limit it could overwrite internal PAL memory). This
     * relies on the fact that our memory management allocates memory from higher addresses to lower
     * addresses (see also enclave_pages.c). */
    *end = SATURATED_P_SUB(*end, g_pal_internal_mem_size, *start);

    if (*end <= *start) {
        log_error("Not enough enclave memory, please increase enclave size!\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
}

PAL_NUM _DkGetProcessId(void) {
    return g_linux_state.process_id;
}

#include "dynamic_link.h"
#include "elf-x86_64.h"

static struct link_map g_pal_map;

/*
 * Takes a pointer+size to an untrusted memory region containing a
 * NUL-separated list of strings. It builds an argv-style list in trusted memory
 * with those strings.
 *
 * It is responsible for handling the access to untrusted memory safely
 * (returns NULL on error) and ensures that all strings are properly
 * terminated. The content of the strings is NOT further sanitized.
 *
 * The argv-style list is allocated on the heap and the caller is responsible
 * to free it (For argv and envp we rely on auto free on termination in
 * practice).
 */
static const char** make_argv_list(void* uptr_src, size_t src_size) {
    const char** argv;

    if (src_size == 0) {
        argv = malloc(sizeof(char*));
        if (argv)
            argv[0] = NULL;
        return argv;
    }

    char* data = malloc(src_size);
    if (!data) {
        return NULL;
    }

    if (!sgx_copy_to_enclave(data, src_size, uptr_src, src_size)) {
        goto fail;
    }
    data[src_size - 1] = '\0';

    size_t argc = 0;
    for (size_t i = 0; i < src_size; i++) {
        if (data[i] == '\0') {
            argc++;
        }
    }

    size_t argv_size;
    if (__builtin_mul_overflow(argc + 1, sizeof(char*), &argv_size)) {
        goto fail;
    }
    argv = malloc(argv_size);
    if (!argv) {
        goto fail;
    }
    argv[argc] = NULL;

    size_t data_i = 0;
    for (size_t arg_i = 0; arg_i < argc; arg_i++) {
        argv[arg_i] = &data[data_i];
        while (data[data_i] != '\0') {
            data_i++;
        }
        data_i++;
    }

    return argv;

fail:
    free(data);
    return NULL;
}
extern void* g_enclave_base;
extern void* g_enclave_top;

/* Graphene uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with a default canary and then updates it to a random one, so we disable stack protector here */
__attribute__((__optimize__("-fno-stack-protector")))
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             struct pal_sec* uptr_sec_info) {
    /* Our arguments are coming directly from the urts. We are responsible to check them. */
    int ret;

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0) {
        log_error("_DkSystemTimeQuery() failed: %d\n", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_state.alloc_align = _DkGetAllocationAlignment();
    assert(IS_POWER_OF_2(g_pal_state.alloc_align));

    struct pal_sec sec_info;
    if (!sgx_copy_to_enclave(&sec_info, sizeof(sec_info), uptr_sec_info, sizeof(*uptr_sec_info))) {
        log_error("Copying sec_info into the enclave failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_pal_sec.heap_min = GET_ENCLAVE_TLS(heap_min);
    g_pal_sec.heap_max = GET_ENCLAVE_TLS(heap_max);

    /* Skip URI_PREFIX_FILE. */
    if (libpal_uri_len < URI_PREFIX_FILE_LEN) {
        log_error("Invalid libpal_uri length (missing \"%s\" prefix?)\n", URI_PREFIX_FILE);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_uri_len -= URI_PREFIX_FILE_LEN;
    uptr_libpal_uri += URI_PREFIX_FILE_LEN;

    /* At this point we don't yet have memory manager, so we cannot allocate memory dynamically. */
    static char libpal_path[1024 + 1];
    if (libpal_uri_len >= sizeof(libpal_path)
            || !sgx_copy_to_enclave(libpal_path, sizeof(libpal_path) - 1, uptr_libpal_uri,
                                    libpal_uri_len)) {
        log_error("Copying libpal_path into the enclave failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_path[libpal_uri_len] = '\0';

    /* relocate PAL itself */
    g_pal_map.l_addr = elf_machine_load_address();
    g_pal_map.l_name = libpal_path;
    elf_get_dynamic_info((void*)g_pal_map.l_addr + elf_machine_dynamic(), g_pal_map.l_info,
                         g_pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&g_pal_map);

    /*
     * We can't verify the following arguments from the urts. So we copy
     * them directly but need to be careful when we use them.
     */

    g_pal_sec.instance_id = sec_info.instance_id;

    // TODO: remove after migrating exec handling to LibOS.
    COPY_ARRAY(g_pal_sec.exec_name, sec_info.exec_name);
    g_pal_sec.exec_name[sizeof(g_pal_sec.exec_name) - 1] = '\0';

    g_pal_sec.stream_fd = sec_info.stream_fd;

    COPY_ARRAY(g_pal_sec.pipe_prefix, sec_info.pipe_prefix);
    g_pal_sec.qe_targetinfo = sec_info.qe_targetinfo;
#ifdef DEBUG
    g_pal_sec.in_gdb = sec_info.in_gdb;
#endif

    /* For {p,u,g}ids we can at least do some minimal checking. */

    /* ppid should be positive when interpreted as signed. It's 0 if we don't
     * have a graphene parent process. */
    if (sec_info.ppid > INT32_MAX) {
        log_error("Invalid sec_info.ppid: %u\n", sec_info.ppid);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.ppid = sec_info.ppid;

    /* As ppid but we always have a pid, so 0 is invalid. */
    if (sec_info.pid > INT32_MAX || sec_info.pid == 0) {
        log_error("Invalid sec_info.pid: %u\n", sec_info.pid);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.pid = sec_info.pid;

    /* -1 is treated as special value for example by chown. */
    if (sec_info.uid == (PAL_IDX)-1 || sec_info.gid == (PAL_IDX)-1) {
        log_error("Invalid sec_info.gid: %u\n", sec_info.gid);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.uid = sec_info.uid;
    g_pal_sec.gid = sec_info.gid;

    int online_logical_cores = sec_info.online_logical_cores;
    if (online_logical_cores >= 1 && online_logical_cores <= (1 << 16)) {
        g_pal_sec.online_logical_cores = online_logical_cores;
    } else {
        log_error("Invalid sec_info.online_logical_cores: %d\n", online_logical_cores);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (sec_info.physical_cores_per_socket <= 0) {
        log_error("Invalid sec_info.physical_cores_per_socket: %ld\n",
                  sec_info.physical_cores_per_socket);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.physical_cores_per_socket = sec_info.physical_cores_per_socket;

    /* set up page allocator and slab manager */
    init_slab_mgr(g_page_size);
    init_untrusted_slab_mgr();
    init_enclave_pages();
    init_enclave_key();

    init_cpuid();
    init_tsc();

    /* now we can add a link map for PAL itself */
    setup_pal_map(&g_pal_map);

    /* initialize enclave properties */
    ret = init_enclave();
    if (ret) {
        log_error("Failed to initialize enclave properties: %d\n", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (args_size > MAX_ARGS_SIZE || env_size > MAX_ENV_SIZE) {
        log_error("Invalid args_size (%lu) or env_size (%lu)\n", args_size, env_size);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        log_error("Creating arguments failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        log_error("Creating environments failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_linux_state.uid = g_pal_sec.uid;
    g_linux_state.gid = g_pal_sec.gid;
    /* TODO: guard this from malicious host. https://github.com/oscarlab/graphene/issues/2087 */
    g_linux_state.process_id = g_pal_sec.pid;

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

    /* Allocate enclave memory to store "logical core -> socket" mappings */
    int* cpu_socket = (int*)malloc(online_logical_cores * sizeof(int));
    if (!cpu_socket) {
        log_error("Allocation for logical core -> socket mappings failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (!sgx_copy_to_enclave(cpu_socket, online_logical_cores * sizeof(int), sec_info.cpu_socket,
                             online_logical_cores * sizeof(int))) {
        log_error("Copying cpu_socket into the enclave failed\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.cpu_socket = cpu_socket;

    /* initialize master key (used for pipes' encryption for all enclaves of an application); it
     * will be overwritten below in init_child_process() with inherited-from-parent master key if
     * this enclave is child */
    ret = _DkRandomBitsRead(&g_master_key, sizeof(g_master_key));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d\n", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* if there is a parent, create parent handle */
    PAL_HANDLE parent = NULL;
    if (g_pal_sec.ppid) {
        if ((ret = init_child_process(&parent)) < 0) {
            log_error("Failed to initialize child process: %d\n", ret);
            ocall_exit(1, /*is_exitgroup=*/true);
        }
    }

    uint64_t manifest_size = GET_ENCLAVE_TLS(manifest_size);
    void* manifest_addr = g_enclave_top - ALIGN_UP_PTR_POW2(manifest_size, g_page_size);

    g_pal_control.manifest_preload.start = (PAL_PTR)manifest_addr;
    g_pal_control.manifest_preload.end   = (PAL_PTR)manifest_addr + manifest_size;

    /* parse manifest */
    char errbuf[256];
    toml_table_t* manifest_root = toml_parse(manifest_addr, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        log_error("PAL failed at parsing the manifest: %s\n"
                  "  Graphene switched to the TOML format recently, please update the manifest\n"
                  "  (in particular, string values must be put in double quotes)\n", errbuf);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_state.raw_manifest_data = manifest_addr;
    g_pal_state.manifest_root = manifest_root;

    ret = toml_sizestring_in(g_pal_state.manifest_root, "loader.pal_internal_mem_size",
                             /*defaultval=*/0, &g_pal_internal_mem_size);
    if (ret < 0) {
        log_error("Cannot parse \'loader.pal_internal_mem_size\' "
                  "(the value must be put in double quotes!)\n");
        ocall_exit(1, true);
    }

    if ((ret = init_trusted_files()) < 0) {
        log_error("Failed to load the checksums of trusted files: %d\n", ret);
        ocall_exit(1, true);
    }

    if ((ret = init_file_check_policy()) < 0) {
        log_error("Failed to load the file check policy: %d\n", ret);
        ocall_exit(1, true);
    }

    if ((ret = init_protected_files()) < 0) {
        log_error("Failed to initialize protected files: %d\n", ret);
        ocall_exit(1, true);
    }

    /* set up thread handle */
    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tcs = g_enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    /* child threads are assigned TIDs 2,3,...; see pal_start_thread() */
    first_thread->thread.tid = 1;
    g_pal_control.first_thread = first_thread;
    SET_ENCLAVE_TLS(thread, &first_thread->thread);

    uint64_t stack_protector_canary;
    ret = _DkRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d\n", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);

    g_pal_enclave_state.enclave_flags |= PAL_ENCLAVE_INITIALIZED;

    /* call main function */
    pal_main(g_pal_sec.instance_id, g_pal_sec.exec_name, parent, first_thread, arguments, environments);
}
