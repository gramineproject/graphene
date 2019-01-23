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
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "api.h"

#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>
#include <sys/types.h>

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
asm (".global pal_start \n"
     "  .type pal_start,@function \n"
     "pal_start: \n "
     "  movq %rsp, %rdi \n"
     "  call pal_bsd_main@PLT \n");

#define RTLD_BOOTSTRAP

/* pal_start is the entry point of libpal.so, which calls pal_main */
#define _ENTRY pal_start

struct pal_bsd_state bsd_state;
struct pal_sec pal_sec;

static int pagesz = PRESET_PAGESIZE;
static uid_t uid;
static gid_t gid;

static void pal_init_bootstrap (void * args, const char ** pal_name,
                                int * pargc,
                                const char *** pargv,
                                const char *** penvp,
                                ElfW(Addr) * baseaddr)
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

    /* Workaround because sometimes BSD misaligns arguments on stack */
    if (all_args[0] == 0)
        all_args++;

    int argc = (uintptr_t) all_args[0];
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;

    /* fetch environment information from aux vectors */
    void ** auxv = (void **) envp + 1;
    for (; *(auxv - 1); auxv++);
    ElfW(auxv_t) *av;
    ElfW(Addr) base = 0;
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
            case AT_BASE:
                base = (ElfW(Addr)) av->a_un.a_val;
                break;
        }

    *pal_name = argv[0];
    argv++;
    argc--;
    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
    *baseaddr = base;
}

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
    void * end_addr, * start_addr;

    if ((void *) TEXT_START - (void *) USER_ADDRESS_LOWEST >
        (void *) USER_ADDRESS_HIGHEST - (void *) DATA_END){
        end_addr = (void *) ALLOC_ALIGNDOWN(TEXT_START);
        start_addr = pal_sec.user_addr_base ? :
            (void *) USER_ADDRESS_LOWEST;
    } else {
        end_addr = (void *) USER_ADDRESS_HIGHEST;
        start_addr = (void *) ALLOC_ALIGNUP(DATA_END);
    }

    assert(ALLOC_ALIGNED(start_addr) && ALLOC_ALIGNED(end_addr));

    while (1) {
        if (start_addr >= end_addr)
            init_fail(PAL_ERROR_NOMEM, "no user memory available");

        void * mem = (void *) ARCH_MMAP(start_addr,
                                        pal_state.alloc_align,
                                        PROT_NONE,
                                        MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                                        -1, 0);
        if (!IS_ERR_P(mem)) {
            INLINE_SYSCALL(munmap, 2, mem, pal_state.alloc_align);
            if (mem == start_addr)
                break;
        }

        start_addr = (void *) ((unsigned long) start_addr << 1);
    }

    *end   = (PAL_PTR) end_addr - USER_ADDRESS_RESERVED;
    *start = (PAL_PTR) start_addr;
}

PAL_NUM _DkGetProcessId (void)
{
    return (bsd_state.start_time & (~0xffff)) | bsd_state.pid;
}

PAL_NUM _DkGetHostId (void)
{
    return 0;
}

#include "dynamic_link.h"

void setup_pal_map (struct link_map * map);

static struct link_map pal_map;

#ifdef __x86_64__
# include "elf-x86_64.h"
#endif

void pal_bsd_main (void * args)
{
    const char * pal_name = NULL;
    PAL_HANDLE parent = NULL, exec = NULL, manifest = NULL;
    const char ** argv, ** envp;
    int argc, ret;

    struct timeval time;
    INLINE_SYSCALL(gettimeofday, 2, &time, NULL);

    /* parse argc, argv, envp and auxv */
    pal_init_bootstrap(args, &pal_name, &argc, &argv, &envp, &pal_map.l_addr);
    pal_map.l_name = pal_name;
    elf_get_dynamic_info((void *) pal_map.l_addr + elf_machine_dynamic(),
                         pal_map.l_info, pal_map.l_addr);
    ELF_DYNAMIC_RELOCATE(&pal_map);

    init_slab_mgr(pagesz);
    setup_pal_map(&pal_map);

    bsd_state.start_time = 1000000ULL * time.tv_sec + time.tv_usec;
    bsd_state.pid = INLINE_SYSCALL(getpid, 0);
    bsd_state.uid = uid;
    bsd_state.gid = gid;
    
    if (!bsd_state.parent_pid)
        bsd_state.parent_pid = bsd_state.pid;

    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tid = bsd_state.pid;

    init_child_process(&parent, &exec, &manifest);
    if (parent)
        goto done_init;

    int fd = INLINE_SYSCALL(open, 3, argv[0], O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(fd))
        goto done_init;


    int len = strlen(argv[0]);
    PAL_HANDLE file = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(file, file);
    file->hdr.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    file->file.fd = fd;
    char * path = (void *) file + HANDLE_SIZE(file);
    get_norm_path(argv[0], path, 0, len + 1);
    file->file.realpath = path;

    if (!check_elf_object(file)) {
        exec = file;
        goto done_init;

    }
    manifest = file;

done_init:
    if (!parent && !exec && !manifest) {
        printf("USAGE: %s [executable|manifest] args ...\n", pal_name);
        _DkProcessExit(0);
        return;
    }
    signal_setup();

    /* jump to main function */
    pal_main(bsd_state.parent_pid, manifest, exec, NULL, parent, first_thread, argv, envp);
}

/* the following code is borrowed from CPUID */

#define WORD_EAX  0
#define WORD_EBX  1
#define WORD_ECX  2
#define WORD_EDX  3
#define WORD_NUM  4

static void cpuid (int cpuid_fd, unsigned int reg,
                   unsigned int words[], unsigned int ecx)
{
   asm("cpuid"
       : "=a" (words[WORD_EAX]),
         "=b" (words[WORD_EBX]),
         "=c" (words[WORD_ECX]),
         "=d" (words[WORD_EDX])
       : "a" (reg),
         "c" (ecx));
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
           "dts"     // "debug store"
           "tm",     // "thermal monitor and clock ctrl"
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
    cpuid(2, 0, words, 0);

    FOUR_CHARS_VALUE(&vendor_id[0], words[WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[WORD_ECX]);
    ci->cpu_vendor = vendor_id;

    char * brand = malloc(48);
    cpuid(-2, 0x80000002, words, 0);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * WORD_NUM);
    cpuid(-2, 0x80000003, words, 0);
    memcpy(&brand[16], words, sizeof(unsigned int) * WORD_NUM);
    cpuid(-2, 0x80000004, words, 0);
    memcpy(&brand[32], words, sizeof(unsigned int) * WORD_NUM);
    ci->cpu_brand = brand;

    cpuid(2, 1, words, 0);
    ci->cpu_family   = BIT_EXTRACT_LE(words[WORD_EAX],  8, 12) + 1;
    ci->cpu_model    = BIT_EXTRACT_LE(words[WORD_EAX],  4,  8);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[WORD_EAX],  0,  4);

    /* According to SDM: EBX[15:0] is to enumerate processor topology 
     * of the system. However this value is intended for display/diagnostic
     * purposes. The actual number of logical processors available to
     * BIOS/OS/App may be different. We use this leaf for now as it's the 
     * best option we have so far to get the cpu number  */

    cpuid(0xb, 1, words, 0);
    ci->cpu_num      = BIT_EXTRACT_LE(words[WORD_EBX],  0, 16);

    int flen = 0, fmax = 80;
    char * flags = malloc(fmax);

    for (int i = 0 ; i < 32 ; i++) {
        if (!cpu_flags[i])
            break;

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
