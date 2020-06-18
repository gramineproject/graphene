/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * db_main.c
 *
 * This file contains the main function of the PAL loader, which loads and
 * processes environment, arguments and manifest.
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

#include <asm/ioctls.h>
#include <asm/mman.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

#include "ecall_types.h"
#include "enclave_pages.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_linux_state linux_state;
struct pal_sec pal_sec;

PAL_SESSION_KEY g_master_key = {0};

size_t g_page_size = PRESET_PAGESIZE;

unsigned long _DkGetAllocationAlignment (void)
{
    return g_page_size;
}

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end, PAL_NUM* gap) {
    *start = (PAL_PTR)pal_sec.heap_min;
    *end   = (PAL_PTR)get_enclave_heap_top();

    /* FIXME: hack to keep some heap for internal PAL objects allocated at runtime (recall that
     * LibOS does not keep track of PAL memory, so without this hack it could overwrite internal
     * PAL memory). This hack is probabilistic and brittle. */
    *end = SATURATED_P_SUB(*end, 2 * 1024 * g_page_size, *start);  /* 8MB reserved for PAL stuff */
    if (*end <= *start) {
        SGX_DBG(DBG_E, "Not enough enclave memory, please increase enclave size!\n");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    *gap = MEMORY_GAP;
}

PAL_NUM _DkGetProcessId (void)
{
    return linux_state.process_id;
}

PAL_NUM _DkGetHostId (void)
{
    return 0;
}

#include "elf-x86_64.h"
#include "dynamic_link.h"
#include <asm/errno.h>

static struct link_map pal_map;

/*
 * Creates a dummy file handle with the given name.
 *
 * The handle is not backed by any file. Reads will return EOF and writes will
 * fail.
 */
static PAL_HANDLE setup_dummy_file_handle (const char * name)
{
    if (!strstartswith_static(name, URI_PREFIX_FILE))
        return NULL;

    name += URI_PREFIX_FILE_LEN;
    size_t len = strlen(name) + 1;
    PAL_HANDLE handle = malloc(HANDLE_SIZE(file) + len);
    SET_HANDLE_TYPE(handle, file);
    HANDLE_HDR(handle)->flags |= RFD(0);
    handle->file.fd = PAL_IDX_POISON;

    char * path = (void *) handle + HANDLE_SIZE(file);
    int ret = get_norm_path(name, path, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", name, pal_strerror(ret));
        free(handle);
        return NULL;
    }
    handle->file.realpath = path;

    handle->file.total  = 0;
    handle->file.stubs  = NULL;

    return handle;
}

static int loader_filter (const char * key, int len)
{
    if (len > 7 && key[0] == 'l' && key[1] == 'o' && key[2] == 'a' && key[3] == 'd' &&
        key[4] == 'e' && key[5] == 'r' && key[6] == '.')
        return 0;

    if (len > 4 && key[0] == 's' && key[1] == 'g' && key[2] == 'x' && key[3] == '.')
        return 0;

    return 1;
}

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
        argv = malloc(sizeof(char *));
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

extern void * enclave_base;
extern void * enclave_top;

void pal_linux_main(char * uptr_args, uint64_t args_size,
                    char * uptr_env, uint64_t env_size,
                    struct pal_sec * uptr_sec_info)
{
    /*
     * Our arguments are comming directly from the urts. We are responsible to
     * check them.
     */

    PAL_HANDLE parent = NULL;
    unsigned long start_time = _DkSystemTimeQuery();
    int rv;

    struct pal_sec sec_info;
    if (!sgx_copy_to_enclave(&sec_info, sizeof(sec_info), uptr_sec_info, sizeof(sec_info))) {
        return;
    }

    pal_sec.heap_min = GET_ENCLAVE_TLS(heap_min);
    pal_sec.heap_max = GET_ENCLAVE_TLS(heap_max);
    pal_sec.exec_addr = GET_ENCLAVE_TLS(exec_addr);
    pal_sec.exec_size = GET_ENCLAVE_TLS(exec_size);

    /* Zero the heap. We need to take care to not zero the exec area. */

    void* zero1_start = pal_sec.heap_min;
    void* zero1_end = pal_sec.heap_max;

    void* zero2_start = pal_sec.heap_max;
    void* zero2_end = pal_sec.heap_max;

    if (pal_sec.exec_addr != NULL) {
        zero1_end = MIN(zero1_end, SATURATED_P_SUB(pal_sec.exec_addr, MEMORY_GAP, 0));
        zero2_start = SATURATED_P_ADD(pal_sec.exec_addr + pal_sec.exec_size, MEMORY_GAP, zero2_end);
    }

    memset(zero1_start, 0, zero1_end - zero1_start);
    memset(zero2_start, 0, zero2_end - zero2_start);

    /* relocate PAL itself */
    pal_map.l_addr = elf_machine_load_address();
    pal_map.l_name = ENCLAVE_PAL_FILENAME;
    elf_get_dynamic_info((void *) pal_map.l_addr + elf_machine_dynamic(),
                         pal_map.l_info, pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&pal_map);

    /*
     * We can't verify the following arguments from the urts. So we copy
     * them directly but need to be careful when we use them.
     */

    pal_sec.instance_id = sec_info.instance_id;

    COPY_ARRAY(pal_sec.exec_name, sec_info.exec_name);
    pal_sec.exec_name[sizeof(pal_sec.exec_name) - 1] = '\0';

    COPY_ARRAY(pal_sec.manifest_name, sec_info.manifest_name);
    pal_sec.manifest_name[sizeof(pal_sec.manifest_name) - 1] = '\0';

    pal_sec.stream_fd = sec_info.stream_fd;

    COPY_ARRAY(pal_sec.pipe_prefix, sec_info.pipe_prefix);
    pal_sec.qe_targetinfo = sec_info.qe_targetinfo;
#ifdef DEBUG
    pal_sec.in_gdb = sec_info.in_gdb;
#endif
#if PRINT_ENCLAVE_STAT == 1
    pal_sec.start_time = sec_info.start_time;
#endif

    /* For {p,u,g}ids we can at least do some minimal checking. */

    /* ppid should be positive when interpreted as signed. It's 0 if we don't
     * have a graphene parent process. */
    if (sec_info.ppid > INT32_MAX) {
        return;
    }
    pal_sec.ppid = sec_info.ppid;

    /* As ppid but we always have a pid, so 0 is invalid. */
    if (sec_info.pid > INT32_MAX || sec_info.pid == 0) {
        return;
    }
    pal_sec.pid = sec_info.pid;

    /* -1 is treated as special value for example by chown. */
    if (sec_info.uid == (PAL_IDX)-1 || sec_info.gid == (PAL_IDX)-1) {
        return;
    }
    pal_sec.uid = sec_info.uid;
    pal_sec.gid = sec_info.gid;

    int num_cpus = sec_info.num_cpus;
    if (num_cpus >= 1 && num_cpus <= (1 << 16)) {
        pal_sec.num_cpus = num_cpus;
    } else {
        return;
    }

    /* set up page allocator and slab manager */
    init_slab_mgr(g_page_size);
    init_untrusted_slab_mgr();
    init_enclave_pages();
    init_enclave_key();

    init_cpuid();

    /* now we can add a link map for PAL itself */
    setup_pal_map(&pal_map);

    /* Set the alignment early */
    pal_state.alloc_align = g_page_size;

    /* initialize enclave properties */
    rv = init_enclave();
    if (rv) {
        SGX_DBG(DBG_E, "Failed to initialize enclave properties: %d\n", rv);
        ocall_exit(rv, /*is_exitgroup=*/true);
    }

    if (args_size > MAX_ARGS_SIZE || env_size > MAX_ENV_SIZE) {
        return;
    }
    const char** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        return;
    }
    const char** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        return;
    }

    pal_state.start_time = start_time;

    linux_state.uid = pal_sec.uid;
    linux_state.gid = pal_sec.gid;
    linux_state.process_id = (start_time & (~0xffff)) | pal_sec.pid;

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

    /* initialize master key (used for pipes' encryption for all enclaves of an application); it
     * will be overwritten below in init_child_process() with inherited-from-parent master key if
     * this enclave is child */
    int ret = _DkRandomBitsRead(&g_master_key, sizeof(g_master_key));
    if (ret < 0)
        return;

    /* if there is a parent, create parent handle */
    if (pal_sec.ppid) {
        if ((rv = init_child_process(&parent)) < 0) {
            SGX_DBG(DBG_E, "Failed to initialize child process: %d\n", rv);
            ocall_exit(rv, /*is_exitgroup=*/true);
        }
    }

    /* now let's mark our enclave as initialized */
    pal_enclave_state.enclave_flags |= PAL_ENCLAVE_INITIALIZED;

    /*
     * We create dummy handles for exec and manifest here to make the logic in
     * pal_main happy and pass the path of them. The handles can't be used to
     * read anything.
     */

    PAL_HANDLE manifest, exec = NULL;

    manifest = setup_dummy_file_handle(pal_sec.manifest_name);

    if (pal_sec.exec_name[0] != '\0') {
        exec = setup_dummy_file_handle(pal_sec.exec_name);
    } else {
        SGX_DBG(DBG_I, "Run without executable\n");
    }

    uint64_t manifest_size = GET_ENCLAVE_TLS(manifest_size);
    void* manifest_addr = enclave_top - ALIGN_UP_PTR_POW2(manifest_size, g_page_size);

    /* parse manifest data into config storage */
    struct config_store* root_config = malloc(sizeof(struct config_store));
    root_config->raw_data = manifest_addr;
    root_config->raw_size = manifest_size;
    root_config->malloc = malloc;
    root_config->free = free;

    const char * errstring = NULL;
    if ((rv = read_config(root_config, loader_filter, &errstring)) < 0) {
        SGX_DBG(DBG_E, "Can't read manifest: %s, error code %d\n", errstring, rv);
        ocall_exit(rv, /*is_exitgroup=*/true);
    }

    pal_state.root_config = root_config;
    __pal_control.manifest_preload.start = (PAL_PTR) manifest_addr;
    __pal_control.manifest_preload.end = (PAL_PTR) manifest_addr + manifest_size;

    if ((rv = init_trusted_files()) < 0) {
        SGX_DBG(DBG_E, "Failed to load the checksums of trusted files: %d\n", rv);
        ocall_exit(rv, true);
    }

    if ((rv = init_trusted_children()) < 0) {
        SGX_DBG(DBG_E, "Failed to load the measurement of trusted child enclaves: %d\n", rv);
        ocall_exit(rv, true);
    }

    if ((rv = init_file_check_policy()) < 0) {
        SGX_DBG(DBG_E, "Failed to load the file check policy: %d\n", rv);
        ocall_exit(rv, true);
    }

#if PRINT_ENCLAVE_STAT == 1
    printf("                >>>>>>>> "
           "Enclave loading time =      %10ld milliseconds\n",
           _DkSystemTimeQuery() - pal_sec.start_time);
#endif

    /* set up thread handle */
    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tcs =
        enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    __pal_control.first_thread = first_thread;
    SET_ENCLAVE_TLS(thread, &first_thread->thread);

    /* call main function */
    pal_main(pal_sec.instance_id, manifest, exec,
             pal_sec.exec_addr, parent, first_thread,
             arguments, environments);
}

