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

#include "api.h"
#include "bogomips.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
__asm__ (".global pal_start\n"
     "  .type pal_start,@function\n"
     "pal_start:\n"
     "  movq %rsp, %rdi\n"
     "  andq $~15, %rsp\n"
     "  call pal_linux_main\n");

#define RTLD_BOOTSTRAP

/* pal_start is the entry point of libpal.so, which calls pal_main */
#define _ENTRY pal_start

/* use objfile-gdb convention instead of .debug_gdb_scripts */
#ifdef DEBUG
__asm__ (".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\r\n"
     ".byte 1\r\n"
     ".asciz \"" PAL_FILE("host/Linux/pal-gdb.py") "\"\r\n"
     ".popsection\r\n");
#endif

struct pal_linux_state linux_state;
struct pal_sec pal_sec;

static size_t g_page_size = PRESET_PAGESIZE;
static int uid, gid;
#if USE_VDSO_GETTIME == 1
static ElfW(Addr) sysinfo_ehdr;
#endif

static void pal_init_bootstrap (void * args, const char ** pal_name,
                                int * pargc,
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
    const char ** e = envp;
#ifdef DEBUG
    for (; *e ; e++)
        if ((*e)[0] == 'I' && (*e)[1] == 'N' && (*e)[2] == '_' &&
            (*e)[3] == 'G' && (*e)[4] == 'D' && (*e)[5] == 'B' &&
            (*e)[6] == '=' && (*e)[7] == '1' && !(*e)[8])
            linux_state.in_gdb = true;
#else
    for (; *e ; e++);
#endif

    ElfW(auxv_t) *av;
    for (av = (ElfW(auxv_t) *) (e + 1) ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_PAGESZ:
                g_page_size = av->a_un.a_val;
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

    *pal_name = argv[0];
    argv++;
    argc--;
    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
}

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
    void* end_addr = (void*)ALLOC_ALIGN_DOWN_PTR(TEXT_START);
    void* start_addr = (void*)USER_ADDRESS_LOWEST;

    assert(IS_ALLOC_ALIGNED_PTR(start_addr) && IS_ALLOC_ALIGNED_PTR(end_addr));

    while (1) {
        if (start_addr >= end_addr)
            INIT_FAIL(PAL_ERROR_NOMEM, "no user memory available");

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

    *end   = (PAL_PTR) end_addr;
    *start = (PAL_PTR) start_addr;

    // Not used, so set it to an empty range.
    *hole_start = start_addr;
    *hole_end = start_addr;
}

PAL_NUM _DkGetProcessId (void)
{
    return linux_state.process_id;
}

PAL_NUM _DkGetHostId (void)
{
    return 0;
}

#include "dynamic_link.h"

void setup_pal_map (struct link_map * map);

#if USE_VDSO_GETTIME == 1
void setup_vdso_map (ElfW(Addr) addr);
#endif

static struct link_map pal_map;

#ifdef __x86_64__
# include "elf-x86_64.h"
#else
# error "unsupported architecture"
#endif

void pal_linux_main (void * args)
{
    const char * pal_name = NULL;
    PAL_HANDLE parent = NULL, exec = NULL, manifest = NULL;
    const char ** argv, ** envp;
    int argc;
    PAL_HANDLE first_thread;

    unsigned long start_time = _DkSystemTimeQueryEarly();

    /* parse argc, argv, envp and auxv */
    pal_init_bootstrap(args, &pal_name, &argc, &argv, &envp);

    pal_map.l_addr = elf_machine_load_address();
    pal_map.l_name = pal_name;
    elf_get_dynamic_info((void *) pal_map.l_addr + elf_machine_dynamic(),
                         pal_map.l_info, pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&pal_map);

    linux_state.environ = envp;

    init_slab_mgr(g_page_size);

    first_thread = malloc(HANDLE_SIZE(thread));
    if (!first_thread)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    SET_HANDLE_TYPE(first_thread, thread);
    first_thread->thread.tid = INLINE_SYSCALL(gettid, 0);

    void * alt_stack = calloc(1, ALT_STACK_SIZE);
    if (!alt_stack)
        INIT_FAIL(PAL_ERROR_NOMEM, "Out of memory");
    first_thread->thread.stack = alt_stack;

    // Initialize TCB at the top of the alternative stack.
    PAL_TCB_LINUX * tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX);
    tcb->common.self = &tcb->common;
    tcb->handle    = first_thread;
    tcb->alt_stack = alt_stack; // Stack bottom
    tcb->callback  = NULL;
    tcb->param     = NULL;
    pal_thread_init(tcb);

    setup_pal_map(&pal_map);

#if USE_VDSO_GETTIME == 1
    if (sysinfo_ehdr)
        setup_vdso_map(sysinfo_ehdr);
#endif

    pal_state.start_time = start_time;
    init_child_process(&parent, &exec, &manifest);

    if (!pal_sec.process_id)
        pal_sec.process_id = INLINE_SYSCALL(getpid, 0);
    linux_state.pid = pal_sec.process_id;

    linux_state.uid = uid;
    linux_state.gid = gid;
    linux_state.process_id = (start_time & (~0xffff)) | linux_state.pid;

    if (!linux_state.parent_process_id)
        linux_state.parent_process_id = linux_state.process_id;

    if (parent)
        goto done_init;

    int fd = INLINE_SYSCALL(open, 3, argv[0], O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(fd)) {
        // DEP 10/20/16: Don't silently swallow permission errors
        // accessing the manifest
        if (fd == -13) {
            printf("Warning: Attempt to open file %s failed with permission denied\n", argv[0]);
        }
        goto done_init;
    }

    size_t len = strlen(argv[0]) + 1;
    PAL_HANDLE file = malloc(HANDLE_SIZE(file) + len);
    SET_HANDLE_TYPE(file, file);
    HANDLE_HDR(file)->flags |= RFD(0)|WFD(0);
    file->file.fd = fd;
    file->file.map_start = NULL;

    char * path = (void *) file + HANDLE_SIZE(file);
    int ret = get_norm_path(argv[0], path, &len);
    if (ret < 0) {
        printf("Could not normalize path (%s): %s\n", argv[0], pal_strerror(ret));
        goto done_init;
    }
    file->file.realpath = path;

    if (!check_elf_object(file)) {
        exec = file;
        goto done_init;
    }

    manifest = file;

done_init:
    if (!parent && !exec && !manifest) {
        printf("Executable not found\n");
        printf("USAGE: %s [executable|manifest] args ...\n", pal_name);
        _DkProcessExit(0);
    }

    signal_setup();

    /* call to main function */
    pal_main((PAL_NUM) linux_state.parent_process_id,
             manifest, exec, NULL, parent, first_thread, argv, envp);
}

/* the following code is borrowed from CPUID */
void cpuid (unsigned int leaf, unsigned int subleaf,
            unsigned int words[])
{
  __asm__ ("cpuid"
      : "=a" (words[PAL_CPUID_WORD_EAX]),
        "=b" (words[PAL_CPUID_WORD_EBX]),
        "=c" (words[PAL_CPUID_WORD_ECX]),
        "=d" (words[PAL_CPUID_WORD_EDX])
      : "a" (leaf),
        "c" (subleaf));
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

/*
 * Returns the number of online CPUs read from /sys/devices/system/cpu/online, -errno on failure.
 * Understands complex formats like "1,3-5,6".
 */
int get_cpu_count(void) {
    int fd = INLINE_SYSCALL(open, 3, "/sys/devices/system/cpu/online", O_RDONLY|O_CLOEXEC, 0);
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

        if (*end == '\0' || *end == ',') {
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

static double get_bogomips(void) {
    int fd = -1;
    char buf[0x800] = { 0 };

    fd = INLINE_SYSCALL(open, 2, "/proc/cpuinfo", O_RDONLY);
    if (fd < 0) {
        return 0.0;
    }

    /* Although the whole file might not fit in this size, the first cpu description should. */
    long x = INLINE_SYSCALL(read, 3, fd, buf, sizeof(buf) - 1);
    INLINE_SYSCALL(close, 1, fd);
    if (x < 0) {
        return 0.0;
    }

    return sanitize_bogomips_value(get_bogomips_from_cpuinfo_buf(buf, sizeof(buf)));
}

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
     * instead we extract info on number of online CPUs by parsing sysfs pseudo-files */
    int cores = get_cpu_count();
    if (cores < 0) {
        free(vendor_id);
        free(brand);
        return cores;
    }
    ci->cpu_num = cores;

    cpuid(1, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  8, 12);
    ci->cpu_model    = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  4,  8);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX],  0,  4);

    if (!memcmp(vendor_id, "GenuineIntel", 12) ||
        !memcmp(vendor_id, "AuthenticAMD", 12)) {
        ci->cpu_family += BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 20, 28);
        ci->cpu_model  += BIT_EXTRACT_LE(words[PAL_CPUID_WORD_EAX], 16, 20) << 4;
    }

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

    ci->cpu_bogomips = get_bogomips();
    if (ci->cpu_bogomips == 0.0) {
        printf("Warning: bogomips could not be retrieved, passing 0.0 to the application\n");
    }

    return rv;
}
