/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE 1
#ifndef __GNUC__
#define __GNUC__ 1
#endif

#include <linux/unistd.h>
#include <asm/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>

#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>
#include <asm-errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "pal_security.h"
#include "utils.h"

struct pal_sec_info * pal_sec_info_addr = NULL;

unsigned long pagesize  = 4096;
unsigned long pageshift = 4095;
unsigned long pagemask  = ~4095;

#if __WORDSIZE == 2
# define FILEBUF_SIZE 512
#else
# define FILEBUF_SIZE 832
#endif

char libname[PATH_MAX];
const char * execname;

int find_manifest (int * pargc, const char *** pargv)
{
    int argc = *pargc;
    const char ** argv = *pargv, * name = *argv;

    if (!argc)
        return -EINVAL;

    int fd = INLINE_SYSCALL(open, 2, name, O_RDONLY|O_CLOEXEC);

    if (IS_ERR(fd))
        return -ERRNO(fd);

    char filebuf[4];
    INLINE_SYSCALL(read, 3, fd, filebuf, 2);

    /* check if the first argument is a manifest, in case it is
       a runnable script. */
    if (!memcmp(filebuf, "#!", 2)) {
        char * path = __alloca(80);
        if (!path)
            return -ENOMEM;

        int bytes = INLINE_SYSCALL(read, 3, fd, path, 80);

        for (int i = 0 ; i < bytes ; i++)
            if (path[i] == ' ' || path[i] == '\n') {
                path[i] = 0;
                bytes = i;
                break;
            }

        memcpy(libname, path, bytes + 1);
        goto opened;
    }

    INLINE_SYSCALL(close, 1, fd);

    memcpy(libname, name, strlen(name) + 1);
    argc--;
    argv++;
    name = *argv;

    if (!argc)
        return -EINVAL;

    fd = INLINE_SYSCALL(open, 2, name, O_RDONLY|O_CLOEXEC);

    if (IS_ERR(fd))
        return -ERRNO(fd);

    /* check if the first argument is a executable. If it is, try finding
       all the possible manifest files */
    INLINE_SYSCALL(read, 3, fd, filebuf, 4);

    if (!memcmp(filebuf, "\177ELF", 4)) {
        int len = strlen(name);
        char * execpath = malloc(len + 1);
        fast_strcpy(execpath, name, len);
        execname = execpath;
        char * filename = __alloca(len + 10);
        fast_strcpy(filename, name, len);
        fast_strcpy(filename + len, ".manifest", 9);

        fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY|O_CLOEXEC);
        if (!IS_ERR(fd))
            goto opened;

        fd = INLINE_SYSCALL(open, 2, "manifest", O_RDONLY|O_CLOEXEC);
        if (!IS_ERR(fd))
            goto opened;

        return -ENOENT;
    }

opened:
    *pargc = argc;
    *pargv = argv;

    return fd;
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

static void get_pal_sec_info (const ElfW(Dyn) * dyn, ElfW(Addr) addr)
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
        return;

    ElfW(Sym) * symtab = (void *) (addr + dt_symtab->d_un.d_ptr);
    const char * strtab = (void *) (addr + dt_strtab->d_un.d_ptr);
    ElfW(Rela) * r = (void *) (addr + dt_rela->d_un.d_ptr);
    ElfW(Rela) * rel = r + dt_relacount->d_un.d_val;
    ElfW(Rela) * end = r + dt_relasz->d_un.d_val / sizeof(ElfW(Rela));

    for (r = rel ; r < end ; r++) {
        ElfW(Sym) * sym = &symtab[ELFW(R_SYM) (r->r_info)];
        if (!sym->st_name)
            continue;
        const char * name = strtab + sym->st_name;
        if (!memcmp(name, "pal_sec_info", 13))
            pal_sec_info_addr = (void *) addr + sym->st_value;
    }
}

static int load_static (const char * filename,
                        unsigned long * entry, unsigned long * load_addr,
                        unsigned long * text_start, unsigned long * text_end,
                        unsigned long * phoff, int * phnum)
{
    int ret = 0;

    int fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY|O_CLOEXEC);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (INTERNAL_SYSCALL_ERROR(ret))
        goto out;

    const ElfW(Ehdr) * header = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + header->e_phoff;
    const ElfW(Phdr) * ph;
    const ElfW(Dyn) * dyn = NULL;
    ElfW(Addr) base = 0;

    *text_start = (unsigned long) -1;
    *text_end = 0;
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
                dyn = (void *) ph->p_vaddr;
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

    ElfW(Addr) addr = INLINE_SYSCALL(mmap, 6, NULL, maplength, c->prot,
                                     MAP_PRIVATE | MAP_FILE, fd, c->mapoff);

    *load_addr = base = addr;
    dyn = (void *) (base + (ElfW(Addr)) dyn);
    goto postmap;

    for ( ; c < &loadcmds[nloadcmds] ; c++) {
        addr = INLINE_SYSCALL(mmap, 6, base + c->mapstart,
                              c->mapend - c->mapstart, c->prot,
                              MAP_PRIVATE | MAP_FILE | MAP_FIXED,
                              fd, c->mapoff);

postmap:
        if (IS_ERR_P(addr)) {
            ret = -ERRNO_P(addr);
            goto out;
        }

        if (c == loadcmds)
            INLINE_SYSCALL(munmap, 2, base + c->mapend,
                           maplength - c->mapend);

        if (c->prot & PROT_EXEC) {
            if (base + c->mapstart < *text_start)
                *text_start = base + c->mapstart;
            if (base + c->mapend > *text_end)
                *text_end = base + c->mapend;
        }

        if (c->allocend > c->dataend) {
            ElfW(Addr) zero, zeroend, zeropage;

            zero = base + c->dataend;
            zeroend = (base + c->allocend + pageshift) & pagemask;
            zeropage = (zero + pageshift) & pagemask;

            if (zeroend < zeropage)
                zeropage = zeroend;

            if (zeropage > zero)
                memset((void *) zero, 0, zeropage - zero);

            if (zeroend > zeropage) {
                addr = INLINE_SYSCALL(mmap, 6,
                                      zeropage, zeroend - zeropage, c->prot,
                                      MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                                      -1, 0);
                if (IS_ERR_P(addr)) {
                    ret = -ERRNO_P(addr);
                    goto out;
                }
            }
        }
    }

    get_pal_sec_info(dyn, base);

    *entry = base + header->e_entry;

out:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
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

struct r_debug {
    int r_version;
    struct link_map * r_map;
    ElfW(Addr) r_brk;
    enum {
        RT_CONSISTENT,
        RT_ADD,
        RT_DELETE
    } r_state;
    ElfW(Addr) r_ldbase;
};

struct r_debug ___r_debug =
    { 1, NULL, (ElfW(Addr)) &___dl_debug_state, RT_CONSISTENT, 0 };

extern __typeof(___r_debug) _r_debug
    __attribute ((alias ("___r_debug")));

static void run_library (unsigned long entry, void * stack,
                         int argc, const char ** argv)
{
    *((void **) (stack -= sizeof(void *))) = NULL;
    for (int i = argc - 1 ; i >= 0 ; i--)
        *((const void **) (stack -= sizeof(void *))) = argv[i];
    *((const void **) (stack -= sizeof(void *))) = libname;
    *((unsigned long *) (stack -= sizeof(unsigned long))) = argc + 1;

    asm volatile ("movq %0, %%rsp\r\n"
                  "pushq %1\r\n"
                  "retq\r\n"
                  :: "r"(stack), "r"(entry) : "memory");
}

int install_syscall_filter (const char * lib_name, unsigned long lib_start,
                            unsigned long lib_end, int trace);
int install_initial_syscall_filter ();

extern bool do_fork;
extern bool do_trace;

int init_child (int argc, const char ** argv, const char ** envp);
int init_parent (pid_t child, int argc, const char ** argv, const char ** envp);
int run_parent (pid_t child, int argc, const char ** argv, const char ** envp);

void start(void);

unsigned long pal_addr = 0;

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

struct config_store root_config;

int free_heaps (void);

void do_main (void * args)
{
    void **all_args = (void **) args;
    int argc = (uintptr_t) all_args[0];
    const char **argv = (const char **) &all_args[1];
    const char **envp = argv + argc + 1;
    ElfW(Addr) addr = 0;
    void ** auxv = (void **) envp;
    ElfW(auxv_t) * av;
    char cfgbuf[CONFIG_MAX];
    int ret = 0;

    while (*(auxv++));

/* VERY IMPORTANT: This is the filter that gets applied to the startup code
 * before applying the real filter in the function install_syscall_filter. If
 * you face any issues, you may have to enable certain syscalls here to
 * successfully make changes to startup code.
 */
    ret = install_initial_syscall_filter();
    if (ret < 0) {
        printf("Unable to install initial system call filter\n");
        goto exit;
    }

    /* occupy PAL_INIT_FD */
    INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);

    for (av = (void *) auxv ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_BASE:
                addr = (ElfW(Addr)) av->a_un.a_val;
                break;
        }

    if (!addr) {
        asm ("leaq start(%%rip), %0\r\n"
             "subq 1f(%%rip), %0\r\n"
             ".section\t.data.rel.ro\r\n"
             "1:\t.quad start\r\n"
             ".previous\r\n"
             : "=r" (addr) : : "cc");
    }

    ElfW(Dyn) * dyn = (ElfW(Dyn) *) (addr + (ElfW(Addr)) &_DYNAMIC);
    do_relocate(dyn, addr);
    init_link_map.l_addr = addr;
    init_link_map.l_ld = dyn;
    init_link_map.l_name = libname;
    ___r_debug.r_map = &init_link_map;
    ___r_debug.r_ldbase = addr;

    int manifest;
    if (!argc || (manifest = find_manifest(&argc, &argv)) < 0) {
        printf("USAGE: %s [executable|manifest] args ...\n", libname);
        goto exit;
    }

    ret = load_manifest(manifest, &root_config);
    if (ret < 0)
        goto exit;

    if (!execname) {
        if (get_config(&root_config, "loader.exec", cfgbuf, CONFIG_MAX) > 0
            && is_file_uri(cfgbuf))
            execname = file_uri_to_path(cfgbuf, strlen(cfgbuf));
    }

    pid_t pid = 0;

    if (do_fork && (pid = INLINE_SYSCALL(fork, 0)) > 0) {
        ret = run_parent(pid, argc, argv, envp);
        goto exit;
    }

    if (IS_ERR(pid)) {
        ret = -ERRNO(pid);
        goto exit;
    }

    unsigned long pal_entry = 0;
    unsigned long pal_start = 0;
    unsigned long pal_end = 0;
    unsigned long pal_phoff = 0;
    int pal_phnum = 0;

    ret = load_static(PAL_LOADER, &pal_entry, &pal_addr, &pal_start, &pal_end,
                      &pal_phoff, &pal_phnum);
    if (ret < 0) {
        printf("Unable to load PAL loader\n");
        goto exit;
    }

    if (!pal_sec_info_addr)
        goto exit;

    int rand = INLINE_SYSCALL(open, 2, "/dev/urandom", O_RDONLY);
    if (IS_ERR(rand)) {
        ret = -ERRNO(rand);
        goto exit;
    }

    ret = INLINE_SYSCALL(mkdir, 2, GRAPHENE_PIPEDIR, 0777);

    if (IS_ERR(ret) && ERRNO(ret) != EEXIST) {
        if (ERRNO(ret) == ENOENT) {
            ret = INLINE_SYSCALL(mkdir, 2, GRAPHENE_TEMPDIR, 0777);

            if (!IS_ERR(ret)) {
                INLINE_SYSCALL(chmod, 2, GRAPHENE_TEMPDIR, 0777);
                ret = INLINE_SYSCALL(mkdir, 2, GRAPHENE_PIPEDIR, 0777);
            }
        }

        if (IS_ERR(ret))
            goto exit;
    }

    if (!IS_ERR(ret))
        INLINE_SYSCALL(chmod, 2, GRAPHENE_PIPEDIR, 0777);

    unsigned int domainid = 0;
    char * tmpdir = __alloca(sizeof(GRAPHENE_PIPEDIR) + 12);
    memcpy(tmpdir, GRAPHENE_PIPEDIR, sizeof(GRAPHENE_PIPEDIR));
    tmpdir[sizeof(GRAPHENE_PIPEDIR) - 1] = '/';

    while (!domainid) {
        ret = INLINE_SYSCALL(read, 3, rand, &domainid,
                             sizeof(unsigned int));
        if (IS_ERR(ret)) {
            ret = -ERRNO(ret);
            goto exit;
        }

        if (domainid) {
            snprintf(tmpdir + sizeof(GRAPHENE_PIPEDIR), 12, "%08x", domainid);
            ret = INLINE_SYSCALL(mkdir, 2, tmpdir, 0700);
            if (IS_ERR(ret)) {
                if ((ret = -ERRNO(ret)) != -EEXIST)
                    goto exit;

                domainid = 0;
            }
        }
    }

    snprintf(pal_sec_info_addr->pipe_prefix, PIPE_MAX, "%08x", domainid);

    unsigned short mcast_port = 0;
    ret = INLINE_SYSCALL(read, 3, rand, &mcast_port, sizeof(mcast_port));
    if (IS_ERR(ret)) {
        ret = -ERRNO(ret);
        goto exit;
    }
    if (mcast_port < 1024) mcast_port += 1024;

    pal_sec_info_addr->domain_id    = domainid;
    pal_sec_info_addr->rand_gen     = rand;
    pal_sec_info_addr->mcast_port   = mcast_port;
    pal_sec_info_addr->_dl_debug_state = &___dl_debug_state;
    pal_sec_info_addr->_r_debug     = &___r_debug;

    ret = init_child(argc, argv, envp);
    if (ret < 0)
        goto exit;

    free_heaps();

    /* free PAL_INIT_FD */
    INLINE_SYSCALL(close, 1, PROC_INIT_FD);

    ret = install_syscall_filter(libname, pal_start, pal_end, do_trace);
    if (ret < 0) {
        printf("Unable to install system call filter\n");
        goto exit;
    }

    /* after installing syscall, you can't execute any system call */

    for (av = (void *) auxv ; av->a_type != AT_NULL ; av++)
        switch (av->a_type) {
            case AT_ENTRY:
                av->a_un.a_val = pal_entry;
                break;
            case AT_BASE:
                av->a_un.a_val = pal_start;
                break;
            case AT_PHDR:
                av->a_un.a_val = pal_start + pal_phoff;
                break;
            case AT_PHNUM:
                av->a_un.a_val = pal_phnum;
                break;
        }

    run_library(pal_entry, envp, argc, argv);

exit:
    INLINE_SYSCALL(exit_group, 1, ret);
}
