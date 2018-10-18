/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE 1
#ifndef __GNUC__
#define __GNUC__ 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fs.h>
#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/errno.h>
#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

#include "pal_security.h"
#include "internal.h"
#include "graphene.h"

#define PRESET_PAGESIZE  (4096UL)

unsigned long pagesize  = PRESET_PAGESIZE;
unsigned long pageshift = PRESET_PAGESIZE - 1;
unsigned long pagemask  = ~(PRESET_PAGESIZE - 1);

# define POOL_SIZE 4096 * 64
static char mem_pool[POOL_SIZE];
static char *bump = mem_pool;
static char *mem_pool_end = &mem_pool[POOL_SIZE];

void * malloc (size_t size)
{
    void * addr = (void *) bump;

    bump += size;
    if (bump >= mem_pool_end) {
        printf("Pal reference monitor out of internal memory!\n");
        INLINE_SYSCALL(exit_group, 1, -1);
        return NULL;
    }

    return addr;
}

void free (void * mem)
{
    /* no freeing */
}

#if __WORDSIZE == 2
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

static void do_bootstrap (void * args, int * pargc, const char *** pargv,
                          const char *** penvp, ElfW(auxv_t) ** pauxv,
                          void ** baseaddr, const char ** program_name)
{
    const char ** all_args = (const char **) args;
    int argc = (uintptr_t) all_args[0];
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;
    void * base = NULL;

    /* fetch environment information from aux vectors */
    void ** auxv = (void **) envp + 1;
    for (; *(auxv - 1); auxv++);
    ElfW(auxv_t) *av;
    for (av = (ElfW(auxv_t) *) auxv ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_PAGESZ:
                pagesize  = av->a_un.a_val;
                pageshift = pagesize - 1;
                pagemask  = ~pageshift;
                break;
            case AT_BASE:
                base = (void *) av->a_un.a_val;
                break;
        }

    if (!base) {
        asm ("leaq start(%%rip), %0\r\n"
             "subq 1f(%%rip), %0\r\n"
             ".section\t.data.rel.ro\r\n"
             "1:\t.quad start\r\n"
             ".previous\r\n"
             : "=r" (base) : : "cc");
    }

    *program_name = *argv;
    argv++;
    argc--;
    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
    *pauxv = (ElfW(auxv_t) *) auxv;
    *baseaddr = base;
}

int open_manifest (const char ** argv)
{
    const char * manifest_name = *argv;
    int ret, fd;

    fd = INLINE_SYSCALL(open, 3, manifest_name, O_RDONLY, 0);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    /* check if the first argument is an executable. If its not,
     * it must be a manifest */

    char filebuf[4], elfmagic[4] = "\177ELF";
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, sizeof(filebuf));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (memcmp(filebuf, elfmagic, sizeof(filebuf)))
        return fd;

    INLINE_SYSCALL(close, 1, fd);

    /* find a manifest file with the same name as executable */
    int len = strlen(*argv);
    manifest_name = __alloca(len + static_strlen(".manifest") + 1);
    memcpy((void *) manifest_name, &argv, len);
    memcpy((void *) manifest_name + len, ".manifest",
           static_strlen(".manifest"));

    fd = INLINE_SYSCALL(open, 3, manifest_name, O_RDONLY, 0);
    if (!IS_ERR(fd))
        return fd;

    /* find "manifest" file */
    fd = INLINE_SYSCALL(open, 3, "manifest", O_RDONLY, 0);
    if (!IS_ERR(fd))
        return fd;

    return -ENOENT;
}

int load_manifest (int fd, struct config_store * config)
{
    int nbytes = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_END);

    if (IS_ERR(nbytes))
        return -ERRNO(nbytes);

    void * config_raw = (void *)
            INLINE_SYSCALL(mmap, 6, NULL, nbytes,
                           PROT_READ|PROT_WRITE, MAP_PRIVATE,
                           fd, 0);

    if (IS_ERR_P(config_raw))
        return -ERRNO_P(config_raw);

    config->raw_data = config_raw;
    config->raw_size = nbytes;
    config->malloc   = malloc;
    config->free     = NULL;

    const char * errstring = NULL;
    int ret = read_config(config, NULL, &errstring);

    if (ret < 0) {
        printf("can't read manifest: %s\n", errstring);
        return ret;
    }

    return 0;
}

static int do_relocate (ElfW(Dyn) * dyn, ElfW(Addr) addr)
{
    ElfW(Dyn) * dt_rela      = NULL;
    ElfW(Dyn) * dt_relacount = NULL;

    for ( ; dyn->d_tag != DT_NULL ; dyn++)
        switch (dyn->d_tag) {
            case DT_RELA:       dt_rela = dyn;      break;
            case DT_RELACOUNT:  dt_relacount = dyn; break;
        }

    if (!dt_rela || !dt_relacount)
        return -EINVAL;

    ElfW(Rela) * r = (void *) (addr + dt_rela->d_un.d_ptr);
    ElfW(Rela) * end = r + dt_relacount->d_un.d_val;

    for ( ; r < end ; r++)
        *(ElfW(Addr) *) (addr + r->r_offset) = addr + r->r_addend;

     return 0;
}

static void *
find_symbol (const ElfW(Dyn) * dyn, ElfW(Addr) addr, const char * name)
{
    const ElfW(Dyn) * dt_symtab    = NULL;
    const ElfW(Dyn) * dt_strtab    = NULL;
    const ElfW(Dyn) * dt_rela      = NULL;
    const ElfW(Dyn) * dt_relasz    = NULL;
    const ElfW(Dyn) * dt_relacount = NULL;

    for ( ; dyn->d_tag != DT_NULL ; dyn++)
        switch (dyn->d_tag) {
            case DT_SYMTAB:     dt_symtab = dyn;    break;
            case DT_STRTAB:     dt_strtab = dyn;    break;
            case DT_RELA:       dt_rela = dyn;      break;
            case DT_RELASZ:     dt_relasz = dyn;    break;
            case DT_RELACOUNT:  dt_relacount = dyn; break;
        }

    if (!dt_symtab || !dt_strtab || !dt_rela || !dt_relasz || !dt_relacount)
        return NULL;

    ElfW(Sym) * symtab = (void *) (addr + dt_symtab->d_un.d_ptr);
    const char * strtab = (void *) (addr + dt_strtab->d_un.d_ptr);
    ElfW(Rela) * r = (void *) (addr + dt_rela->d_un.d_ptr);
    ElfW(Rela) * rel = r + dt_relacount->d_un.d_val;
    ElfW(Rela) * end = r + dt_relasz->d_un.d_val / sizeof(ElfW(Rela));
    int len = strlen(name);

    for (r = rel ; r < end ; r++) {
        ElfW(Sym) * sym = &symtab[ELFW(R_SYM) (r->r_info)];
        if (!sym->st_name)
            continue;
        if (!memcmp(strtab + sym->st_name, name, len + 1))
            return (void *) addr + sym->st_value;
    }

    return NULL;
}

static int load_static (const char * filename, void ** load_addr,
                        void ** entry, ElfW(Dyn) ** dyn,
                        unsigned long * phoff, int * phnum)
{
    int ret = 0;

    int fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY|O_CLOEXEC);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (IS_ERR(ret)) {
        ret = -ERRNO(ret);
        goto out;
    }

    const ElfW(Ehdr) * header = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + header->e_phoff;
    const ElfW(Phdr) * ph;
    ElfW(Addr) base = 0;

    *phoff = header->e_phoff;
    *phnum = header->e_phnum;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        off_t mapoff;
        int prot;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                *dyn = (void *) ph->p_vaddr;
                break;

            case PT_LOAD:
                if (nloadcmds == 16) {
                    ret = -EINVAL;
                    goto out;
                }

                c = &loadcmds[nloadcmds++];
                c->mapstart = ph->p_vaddr & pagemask;
                c->mapend = (ph->p_vaddr + ph->p_filesz + pageshift) & pagemask;
                c->dataend = ph->p_vaddr + ph->p_filesz;
                c->allocend = ph->p_vaddr + ph->p_memsz;
                c->mapoff = ph->p_offset & pagemask;
                c->prot = (ph->p_flags & PF_R ? PROT_READ  : 0) |
                          (ph->p_flags & PF_W ? PROT_WRITE : 0) |
                          (ph->p_flags & PF_X ? PROT_EXEC  : 0);
                break;
        }

    c = loadcmds;
    int maplength = loadcmds[nloadcmds - 1].allocend - c->mapstart;

    base = INLINE_SYSCALL(mmap, 6, NULL, maplength, c->prot,
                          MAP_PRIVATE | MAP_FILE, fd, c->mapoff);

    if (IS_ERR_P(base)) {
        ret = -ERRNO_P(base);
        goto out;
    }

    goto postmap;

    for ( ; c < &loadcmds[nloadcmds] ; c++) {
        ElfW(Addr) addr = INLINE_SYSCALL(mmap, 6, base + c->mapstart,
                                         c->mapend - c->mapstart,
                                         c->prot,
                                         MAP_PRIVATE|MAP_FILE|MAP_FIXED,
                                         fd, c->mapoff);
        if (IS_ERR_P(addr)) {
            ret = -ERRNO_P(addr);
            goto out;
        }

postmap:
        if (c == loadcmds)
            INLINE_SYSCALL(munmap, 2, base + c->mapend, maplength - c->mapend);

        if (c->allocend <= c->dataend)
            continue;

        ElfW(Addr) zero, zeroend, zeropage;

        zero = base + c->dataend;
        zeroend = (base + c->allocend + pageshift) & pagemask;
        zeropage = (zero + pageshift) & pagemask;

        if (zeroend < zeropage)
            zeropage = zeroend;

        if (zeropage > zero)
            memset((void *) zero, 0, zeropage - zero);

        if (zeroend <= zeropage)
            continue;

        addr = INLINE_SYSCALL(mmap, 6, zeropage, zeroend - zeropage, c->prot,
                              MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0);
        if (IS_ERR_P(addr)) {
            ret = -ERRNO_P(addr);
            goto out;
        }
    }

    *dyn = (void *) (base + (ElfW(Addr)) *dyn);
    *load_addr = (void *) base;
    *entry = (void *) base + header->e_entry;

out:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

static int find_code_range (void * load_addr, void ** start, void ** end)
{
    const ElfW(Ehdr) * header = load_addr;
    const ElfW(Phdr) * phdr = load_addr + header->e_phoff, * ph;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            *start = load_addr + ph->p_vaddr;
            *end = load_addr + ph->p_vaddr + ph->p_filesz;
            return 0;
        }

    return -ENOENT;
}

void __attribute__((noinline)) ___dl_debug_state (void) {}

extern __typeof(___dl_debug_state) _dl_debug_state
    __attribute ((alias ("___dl_debug_state")));

struct link_map {
    ElfW(Addr)        l_addr;
    const char *      l_name;
    const ElfW(Dyn) * l_ld;
    struct link_map * l_next, * l_prev;
};

static struct link_map init_link_map;

struct r_debug ___r_debug =
    { 1, NULL, (ElfW(Addr)) &___dl_debug_state, RT_CONSISTENT, 0 };

extern __typeof(___r_debug) _r_debug
    __attribute ((alias ("___r_debug")));

int ioctl_set_graphene (struct config_store * sandbox_config, int npolices,
                        const struct graphene_user_policy * policies);

int set_sandbox (struct config_store * sandbox_config,
                 struct pal_sec * pal_sec_addr, void * pal_addr)
{
    struct graphene_user_policy policies[] = {
        { .type = GRAPHENE_LIB_NAME,    .value = PAL_LOADER, },
        { .type = GRAPHENE_LIB_ADDR,    .value = pal_addr, },
        { .type = GRAPHENE_UNIX_PREFIX, .value = &pal_sec_addr->pipe_prefix_id, },
        { .type = GRAPHENE_MCAST_PORT,  .value = &pal_sec_addr->mcast_port, },
        { .type = GRAPHENE_FS_PATH | GRAPHENE_FS_READ,
          .value = "/proc/meminfo", },
    };

    return ioctl_set_graphene(sandbox_config,
                              sizeof(policies) / sizeof(policies[0]),
                              policies);
}

int install_initial_syscall_filter (void);
int install_syscall_filter (void * code_start, void * code_end);

void start(void);

asm (".global start\r\n"
     "  .type start,@function\r\n"
     ".global main\r\n"
     "  .type do_main,@function\r\n");

/* At the begining of entry point, rsp starts at argc, then argvs,
   envps and auxvs. Here we store rsp to rdi, so it will not be
   messed up by function calls */
asm ("start:\r\n"
     "  movq %rsp, %rdi\r\n"
     "  call do_main\r\n");

void do_main (void * args)
{
    const char * program_name;
    int argc;
    const char ** argv, ** envp;
    ElfW(auxv_t) * auxv;
    void * baseaddr;
    unsigned long pid = INLINE_SYSCALL(getpid, 0);
    int ret = 0;

    do_bootstrap(args, &argc, &argv, &envp, &auxv, &baseaddr, &program_name);

    /* VERY IMPORTANT: This is the filter that gets applied to the startup code
     * before applying the real filter in the function install_syscall_filter.
     * If you face any issues, you may have to enable certain syscalls here to
     * successfully make changes to startup code. */

    ret = install_initial_syscall_filter();
    if (ret < 0) {
        printf("Unable to install initial system call filter\n");
        goto exit;
    }

    /* occupy PAL_INIT_FD */
    INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);

    ElfW(Dyn) * dyn = (ElfW(Dyn) *) (baseaddr + (ElfW(Addr)) &_DYNAMIC);
    do_relocate(dyn, (ElfW(Addr)) baseaddr);

    init_link_map.l_addr = (ElfW(Addr)) baseaddr;
    init_link_map.l_ld   = dyn;
    init_link_map.l_name = program_name;
    ___r_debug.r_map     = &init_link_map;
    ___r_debug.r_ldbase  = (ElfW(Addr)) baseaddr;

    int manifest;
    if (!argc || (manifest = open_manifest(argv)) < 0) {
        printf("USAGE: %s [executable|manifest] args ...\n", program_name);
        goto exit;
    }

    struct config_store sandbox_config;
    ret = load_manifest(manifest, &sandbox_config);
    if (ret < 0)
        goto exit;

    void *        pal_addr  = NULL;
    void *        pal_entry = NULL;
    ElfW(Dyn) *   pal_dyn   = NULL;
    unsigned long pal_phoff = 0;
    int           pal_phnum = 0;

    ret = load_static(PAL_LOADER, &pal_addr, &pal_entry, &pal_dyn,
                      &pal_phoff, &pal_phnum);

    if (ret < 0) {
        printf("Unable to load PAL loader\n");
        goto exit;
    }

    int rand_gen = INLINE_SYSCALL(open, 3, RANDGEN_DEVICE, O_RDONLY, 0);
    if (IS_ERR(rand_gen)) {
        printf("Unable to open random generator device\n");
        goto exit;
    }

    struct pal_sec * pal_sec_addr =
                find_symbol(pal_dyn, (ElfW(Addr)) pal_addr, "pal_sec");
    if (!pal_sec_addr) {
        printf("Unable to find 'pal_sec' in PAL loader\n");
        goto exit;
    }

    unsigned short mcast_port = 0;
    ret = INLINE_SYSCALL(read, 3, rand_gen, &mcast_port, sizeof(mcast_port));
    if (IS_ERR(ret)) {
        ret = -ERRNO(ret);
        goto exit;
    }

    pal_sec_addr->process_id      = pid;
    pal_sec_addr->random_device   = rand_gen;
    pal_sec_addr->pipe_prefix_id  = 0;
    pal_sec_addr->mcast_port      = mcast_port % (65536 - 1024) + 1024;
    pal_sec_addr->_dl_debug_state = &___dl_debug_state;
    pal_sec_addr->_r_debug        = &___r_debug;

    ret = set_sandbox(&sandbox_config, pal_sec_addr, pal_addr);
    if (ret < 0) {
        printf("Unable to load sandbox policies\n");
        goto exit;
    }

    /* free PAL_INIT_FD */
    INLINE_SYSCALL(close, 1, PROC_INIT_FD);

    void * code_start = NULL;
    void * code_end   = NULL;
    ret = find_code_range(pal_addr, &code_start, &code_end);
    if (ret < 0) {
        printf("Unable to find a code segment\n");
        goto exit;
    }

    ret = install_syscall_filter(code_start, code_end);
    if (ret < 0) {
        printf("Unable to install system call filter\n");
        goto exit;
    }

    /* after installing syscall, you can't execute any system call */
    const char ** new_envp, ** new_argv;
    ElfW(auxv_t) * new_auxv;
    int envc = 1, auxc = 1;
    for (const char ** e = envp ; *e ; e++, envc++);
    for (ElfW(auxv_t) * av = auxv ; av->a_type != AT_NULL ; av++, auxc++);

    /* skip 1024 bytes as a red zone */
    void * stack = __alloca(sizeof(unsigned long) +
                            sizeof(char *) * (argc + 2) +
                            sizeof(char *) * envc +
                            sizeof(ElfW(auxv_t)) * auxc);

    *(unsigned long *) stack = argc + 1;
    new_argv = stack + sizeof(unsigned long *);
    new_envp = (void *) &new_argv[argc + 2];
    new_auxv = (void *) &new_envp[envc + 1];
    new_argv[0] = PAL_LOADER;
    memcpy(&new_argv[1], argv, sizeof(char *) * (argc + 1));
    memcpy(new_envp, envp, sizeof(char *) * envc);
    memcpy(new_auxv, auxv, sizeof(ElfW(auxv_t)) * auxc);

    for (ElfW(auxv_t) * av = new_auxv ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_ENTRY:
                av->a_un.a_val = (unsigned long) pal_entry;
                break;
            case AT_BASE:
                av->a_un.a_val = (unsigned long) pal_addr;
                break;
            case AT_PHDR:
                av->a_un.a_val = (unsigned long) pal_addr + pal_phoff;
                break;
            case AT_PHNUM:
                av->a_un.a_val = pal_phnum;
                break;
        }

    asm volatile ("xorq %%rsp, %%rsp\r\n"
                  "movq %0, %%rsp\r\n"
                  "jmpq *%1\r\n"
                  :: "r"(stack), "r"(pal_entry) : "memory");

exit:
    INLINE_SYSCALL(exit_group, 1, ret);
}

/* This does not return */
void __abort(void) {
    INLINE_SYSCALL(exit_group, 1, -1);
}

void warn (const char *format, ...)
{ 
    va_list args;
    va_start (args, format);
    printf(format, args);
    va_end (args);
}

