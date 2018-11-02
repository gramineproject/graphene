/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#include <asm/mman.h>
#include <asm/ioctls.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

#include "ecall_types.h"
#include "enclave_pages.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_linux_state linux_state;
struct pal_sec pal_sec;

unsigned int pagesz = PRESET_PAGESIZE;

unsigned long _DkGetPagesize (void)
{
    return pagesz;
}

unsigned long _DkGetAllocationAlignment (void)
{
    return pagesz;
}

void _DkGetAvailableUserAddressRange (PAL_PTR * start, PAL_PTR * end)
{
    *start = (PAL_PTR) pal_sec.heap_min;
    *end = (PAL_PTR) get_reserved_pages(NULL, pagesz);
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

void setup_pal_map (struct link_map * map);
static struct link_map pal_map;

int init_untrusted_slab_mgr (int pagesize);
int init_enclave (void);
int init_enclave_key (void);
int init_child_process (PAL_HANDLE * parent_handle);

static PAL_HANDLE setup_file_handle (const char * name, int fd)
{
    if (!strpartcmp_static(name, "file:"))
        return NULL;

    name += static_strlen("file:");
    int len = strlen(name);
    PAL_HANDLE handle = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(handle, file);
    HANDLE_HDR(handle)->flags |= RFD(0);
    handle->file.fd = fd;
    handle->file.append = 0;
    handle->file.pass = 0;

    char * path = (void *) handle + HANDLE_SIZE(file);
    get_norm_path(name, path, 0, len + 1);
    handle->file.realpath = path;

    handle->file.total = 0;
    handle->file.stubs = NULL;

    return handle;
}

static int loader_filter (const char * key, int len)
{
    if (key[0] == 'l' && key[1] == 'o' && key[2] == 'a' && key[3] == 'd' &&
        key[4] == 'e' && key[5] == 'r' && key[6] == '.')
        return 0;

    if (key[0] == 's' && key[1] == 'g' && key[2] == 'x' && key[3] == '.')
        return 0;

    return 1;
}

extern void * enclave_base;

void pal_linux_main(const char ** arguments, const char ** environments,
                    struct pal_sec * sec_info)
{
    PAL_HANDLE parent = NULL;
    unsigned long start_time = _DkSystemTimeQuery();
    int rv;

    /* relocate PAL itself */
    pal_map.l_addr = (ElfW(Addr)) sec_info->enclave_addr;
    pal_map.l_name = sec_info->enclave_image;
    elf_get_dynamic_info((void *) pal_map.l_addr + elf_machine_dynamic(),
                         pal_map.l_info, pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&pal_map);

    memcpy(&pal_sec, sec_info, sizeof(struct pal_sec));

    /* set up page allocator and slab manager */
    init_slab_mgr(pagesz);
    init_untrusted_slab_mgr(pagesz);
    init_pages();
    init_enclave_key();

    /* now we can add a link map for PAL itself */
    setup_pal_map(&pal_map);

    /* initialize enclave properties */
    init_enclave();
    pal_state.start_time = start_time;

    /* if there is a parent, create parent handle */
    if (pal_sec.ppid) {
        if ((rv = init_child_process(&parent)) < 0) {
            SGX_DBG(DBG_E, "Failed to initialize child process: %d\n", rv);
            ocall_exit(rv);
        }
    }

    linux_state.uid = pal_sec.uid;
    linux_state.gid = pal_sec.gid;
    linux_state.process_id = (start_time & (~0xffff)) | pal_sec.pid;

    /* now let's mark our enclave as initialized */
    pal_enclave_state.enclave_flags |= PAL_ENCLAVE_INITIALIZED;

    /* create executable handle */
    PAL_HANDLE manifest, exec = NULL;

    /* create manifest handle */
    manifest =
        setup_file_handle(pal_sec.manifest_name, pal_sec.manifest_fd);

    if (pal_sec.exec_fd != PAL_IDX_POISON) {
        exec = setup_file_handle(pal_sec.exec_name, pal_sec.exec_fd);
    } else {
        SGX_DBG(DBG_I, "Run without executable\n");
    }

    /* parse manifest data into config storage */
    struct config_store * root_config =
            malloc(sizeof(struct config_store));
    root_config->raw_data = pal_sec.manifest_addr;
    root_config->raw_size = pal_sec.manifest_size;
    root_config->malloc = malloc;
    root_config->free = free;

    const char * errstring = NULL;
    if ((rv = read_config(root_config, loader_filter, &errstring)) < 0) {
        SGX_DBG(DBG_E, "Can't read manifest: %s, error code %d\n", errstring, rv);
        ocall_exit(rv);
    }

    pal_state.root_config = root_config;
    __pal_control.manifest_preload.start = (PAL_PTR) pal_sec.manifest_addr;
    __pal_control.manifest_preload.end = (PAL_PTR) pal_sec.manifest_addr +
                                         pal_sec.manifest_size;

    init_trusted_files();
    init_trusted_children();

#if PRINT_ENCLAVE_STAT == 1
    printf("                >>>>>>>> "
           "Enclave loading time =      %10ld milliseconds\n",
           _DkSystemTimeQuery() - sec_info->start_time);
#endif

    /* set up thread handle */
    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tcs =
        enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    SET_ENCLAVE_TLS(thread, (__pal_control.first_thread = first_thread));

    /* call main function */
    pal_main(pal_sec.instance_id, manifest, exec,
             pal_sec.exec_addr, parent, first_thread,
             arguments, environments);
}

/* the following code is borrowed from CPUID */

#define WORD_EAX  0
#define WORD_EBX  1
#define WORD_ECX  2
#define WORD_EDX  3
#define WORD_NUM  4

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
   (((unsigned long) (width) >= BPI) ? ~0ULL : POWER2(width)-1ULL)

#define BIT_EXTRACT_LE(value, start, after) \
   (((unsigned long) (value) & RIGHTMASK(after)) >> start)

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

void _DkGetCPUInfo (PAL_CPU_INFO * ci)
{
    unsigned int words[WORD_NUM];

    char * vendor_id = malloc(12);
    cpuid(0, 0, words);

    FOUR_CHARS_VALUE(&vendor_id[0], words[WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[WORD_ECX]);
    ci->cpu_vendor = vendor_id;
    // Must be an Intel CPU
    assert(!memcmp(vendor_id, "GenuineIntel", 12));

    char * brand = malloc(48);
    cpuid(0x80000002, 0, words);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * WORD_NUM);
    cpuid(0x80000003, 0, words);
    memcpy(&brand[16], words, sizeof(unsigned int) * WORD_NUM);
    cpuid(0x80000004, 0, words);
    memcpy(&brand[32], words, sizeof(unsigned int) * WORD_NUM);
    ci->cpu_brand = brand;

    /* According to SDM: EBX[15:0] is to enumerate processor topology 
     * of the system. However this value is intended for display/diagnostic
     * purposes. The actual number of logical processors available to
     * BIOS/OS/App may be different. We use this leaf for now as it's the 
     * best option we have so far to get the cpu number  */

    cpuid(0xb, 1, words);
    ci->cpu_num      = BIT_EXTRACT_LE(words[WORD_EBX], 0, 16);

    cpuid(1, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[WORD_EAX],  8, 12) +
                       BIT_EXTRACT_LE(words[WORD_EAX], 20, 28);
    ci->cpu_model    = BIT_EXTRACT_LE(words[WORD_EAX],  4,  8) +
                      (BIT_EXTRACT_LE(words[WORD_EAX], 16, 20) << 4);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[WORD_EAX],  0,  4);

    int flen = 0, fmax = 80;
    char * flags = malloc(fmax);

    for (int i = 0 ; i < 32 ; i++) {
        if (!cpu_flags[i])
            continue;

        if (BIT_EXTRACT_LE(words[WORD_EDX], i, i + 1)) {
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
}
