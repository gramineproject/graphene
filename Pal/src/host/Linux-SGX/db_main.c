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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"
#include "protected_files.h"

#include <asm/mman.h>
#include <asm/ioctls.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

#include "ecall_types.h"
#include "enclave_pages.h"
#include "lru_cache.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_linux_state linux_state;
struct pal_sec pal_sec;

size_t g_page_size = PRESET_PAGESIZE;

unsigned long _DkGetPagesize (void)
{
    return g_page_size;
}

unsigned long _DkGetAllocationAlignment (void)
{
    return g_page_size;
}

void _DkGetAvailableUserAddressRange (PAL_PTR * start, PAL_PTR * end,
                                      PAL_PTR * hole_start, PAL_PTR * hole_end)
{
    *start = (PAL_PTR) pal_sec.heap_min;
    *end = (PAL_PTR) get_reserved_pages(NULL, g_page_size);
    *hole_start = SATURATED_P_SUB(pal_sec.exec_addr, MEMORY_GAP, *start);
    *hole_end = SATURATED_P_ADD(pal_sec.exec_addr + pal_sec.exec_size, MEMORY_GAP, *end);
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

void setup_pal_map (struct link_map * map);
static struct link_map pal_map;

void init_untrusted_slab_mgr(void);
int init_enclave(void);
int init_enclave_key(void);
int init_child_process(PAL_HANDLE* parent_handle);
void init_cpuid(void);

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
    handle->file.offset = 0;
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
 * NUL-separated list of strings. It builds a argv-style list in trusted memory
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
static const char** make_argv_list(void * uptr_src, uint64_t src_size) {
    const char **argv;

    if (src_size == 0) {
        argv = malloc(sizeof(char *));
        argv[0] = NULL;
        return argv;
    }

    char * data = malloc(src_size);
    if (!data) {
        return NULL;
    }

    if (!sgx_copy_to_enclave(data, src_size, uptr_src, src_size)) {
        goto free_and_err;
    }
    data[src_size - 1] = '\0';

    uint64_t argc = 0;
    for (uint64_t i = 0; i < src_size; i++) {
        if (data[i] == '\0') {
            argc++;
        }
    }

    size_t argv_size;
    if (__builtin_mul_overflow(argc + 1, sizeof(char *), &argv_size)) {
        goto free_and_err;
    }
    argv = malloc(argv_size);
    if (!argv) {
        goto free_and_err;
    }
    argv[argc] = NULL;

    uint64_t data_i = 0;
    for (uint64_t arg_i = 0; arg_i < argc; arg_i++) {
        argv[arg_i] = &data[data_i];
        while (data[data_i] != '\0') {
            data_i++;
        }
        data_i++;
    }

    return argv;

free_and_err:
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
    pal_sec.cargo_fd  = sec_info.cargo_fd;

    COPY_ARRAY(pal_sec.pipe_prefix, sec_info.pipe_prefix);
    pal_sec.aesm_targetinfo = sec_info.aesm_targetinfo;
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
    init_pages();
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
    const char ** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        return;
    }
    const char ** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        return;
    }

    pal_state.start_time = start_time;

    linux_state.uid = pal_sec.uid;
    linux_state.gid = pal_sec.gid;
    linux_state.process_id = (start_time & (~0xffff)) | pal_sec.pid;

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

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
    struct config_store * root_config =
            malloc(sizeof(struct config_store));
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

    if ((rv = init_trusted_platform()) < 0) {
        SGX_DBG(DBG_E, "Failed to verify the platform using remote attestation: %d\n", rv);
        ocall_exit(rv, true);
    }

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

    if ((rv = init_protected_files()) < 0) {
        SGX_DBG(DBG_E, "Failed to initialize protected files: %d\n", rv);
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

    lruc_test();

    /* call main function */
    pal_main(pal_sec.instance_id, manifest, exec,
             pal_sec.exec_addr, parent, first_thread,
             arguments, environments);
}

/* the following code is borrowed from CPUID */

static void cpuid (unsigned int leaf, unsigned int subleaf,
                   unsigned int words[])
{
    _DkCpuIdRetrieve(leaf, subleaf, words);
}

#define FOUR_CHARS_VALUE(s, w)      \
    (s)[0] = (w) & 0xff;            \
    (s)[1] = ((w) >>  8) & 0xff;    \
    (s)[2] = ((w) >> 16) & 0xff;    \
    (s)[3] = ((w) >> 24) & 0xff;

#define BPI  32
#define POWER2(power) \
   (1ULL << (power))
#define RIGHTMASK(width) \
   (((unsigned long)(width) >= BPI) ? ~0ULL : POWER2(width) - 1ULL)

#define BIT_EXTRACT_LE(value, start, after) \
   (((unsigned long)(value) & RIGHTMASK(after)) >> start)

static char * cpu_flags[]
      = { "fpu",    // "x87 FPU on chip"
          "vme",    // "virtual-8086 mode enhancement"
          "de",     // "debugging extensions"
          "pse",    // "page size extensions"
          "tsc",    // "time stamp counter"
          "msr",    // "RDMSR and WRMSR support"
          "pae",    // "physical address extensions"
          "mce",    // "machine check exception"
          "cx8",    // "CMPXCHG8B inst."
          "apic",   // "APIC on chip"
          NULL,
          "sep",    // "SYSENTER and SYSEXIT"
          "mtrr",   // "memory type range registers"
          "pge",    // "PTE global bit"
          "mca",    // "machine check architecture"
          "cmov",   // "conditional move/compare instruction"
          "pat",    // "page attribute table"
          "pse36",  // "page size extension"
          "pn",     // "processor serial number"
          "clflush",    // "CLFLUSH instruction"
          NULL,
          "dts",    // "debug store"
          "acpi",   // "Onboard thermal control"
          "mmx",    // "MMX Technology"
          "fxsr",   // "FXSAVE/FXRSTOR"
          "sse",    // "SSE extensions"
          "sse2",   // "SSE2 extensions"
          "ss",     // "self snoop"
          "ht",     // "hyper-threading / multi-core supported"
          "tm",     // "therm. monitor"
          "ia64",   // "IA64"
          "pbe",    // "pending break event"
        };


int _DkGetCPUInfo (PAL_CPU_INFO * ci)
{
    unsigned int words[PAL_CPUID_WORD_NUM];
    int rv = 0;

    const size_t VENDOR_ID_SIZE = 13;
    char* vendor_id = malloc(VENDOR_ID_SIZE);
    cpuid(0, 0, words);

    FOUR_CHARS_VALUE(&vendor_id[0], words[PAL_CPUID_WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[PAL_CPUID_WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[PAL_CPUID_WORD_ECX]);
    vendor_id[VENDOR_ID_SIZE - 1] = '\0';
    ci->cpu_vendor = vendor_id;
    // Must be an Intel CPU
    if (memcmp(vendor_id, "GenuineIntel", 12)) {
      free(vendor_id);
      return -PAL_ERROR_INVAL;
    }

    const size_t BRAND_SIZE = 49;
    char* brand = malloc(BRAND_SIZE);
    cpuid(0x80000002, 0, words);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    cpuid(0x80000003, 0, words);
    memcpy(&brand[16], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    cpuid(0x80000004, 0, words);
    memcpy(&brand[32], words, sizeof(unsigned int) * PAL_CPUID_WORD_NUM);
    brand[BRAND_SIZE - 1] = '\0';
    ci->cpu_brand = brand;

    /* we cannot use CPUID(0xb) because it counts even disabled-by-BIOS cores (e.g. HT cores);
     * instead, this is passed in via pal_sec at start-up time. */
    ci->cpu_num = pal_sec.num_cpus;

    cpuid(1, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  8, 12) +
                       BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 20, 28);
    ci->cpu_model    = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  4,  8) +
                      (BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 16, 20) << 4);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  0,  4);

    int flen = 0, fmax = 80;
    char * flags = malloc(fmax);

    for (int i = 0 ; i < 32 ; i++) {
        if (!cpu_flags[i])
            continue;

        if (BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EDX], i, i + 1)) {
            int len = strlen(cpu_flags[i]);
            if (flen + len + 1 > fmax) {
                char * new_flags = malloc(fmax * 2);
                memcpy(new_flags, flags, flen);
                free(flags);
                fmax *= 2;
                flags = new_flags;
            }
            memcpy(flags + flen, cpu_flags[i], len);
            flen += len;
            flags[flen++] = ' ';
        }
    }

    flags[flen ? flen - 1 : 0] = 0;
    ci->cpu_flags = flags;
    return rv;
}
