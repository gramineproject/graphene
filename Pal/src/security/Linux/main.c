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
#include "graphene-sandbox.h"

#undef PAL_LOADER
#define PAL_LOADER XSTRINGIFY(RUNTIME_DIR) "/" "libpal-Linux.so"

#define PRESET_PAGESIZE  (4096UL)

unsigned long pagesize  = PRESET_PAGESIZE;
unsigned long pageshift = PRESET_PAGESIZE - 1;
unsigned long pagemask  = ~(PRESET_PAGESIZE - 1);

/* Chia-Che: setting the minimal pool size to 1 page.
   The end of the data segment shouldn't exceed 0x10000 boundary */
#define MIN_POOL_SIZE   PRESET_PAGESIZE
char mem_pool[MIN_POOL_SIZE] __attribute__((section(".pool")));
static char *bump = &__pool_start;
static char *mem_pool_end = &__pool_end;

void * malloc (size_t size)
{
    void * addr = (void *) bump;

    bump += size;
    if (bump >= mem_pool_end) {
        printf("Pal security loader: out of memory\n");
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

static void do_bootstrap (void * args,
                          int * pargc, const char *** pargv,
                          const char *** penvp,
                          ElfW(auxv_t) ** pauxv)
{
    const char ** all_args = (const char **) args;
    int argc = (uintptr_t) all_args[0];
    const char ** argv = &all_args[1];
    const char ** envp = argv + argc + 1;

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
        }

    *pargc = argc;
    *pargv = argv;
    *penvp = envp;
    *pauxv = (ElfW(auxv_t) *) auxv;
}

unsigned int reference_monitor;

int sys_open(const char * path, int flags, int mode)
{
    if (reference_monitor) {
        struct sys_open_param param = {
            .filename = path,
            .flags    = flags,
            .mode     = mode,
        };
        return INLINE_SYSCALL(ioctl, 3, reference_monitor,
                              GRM_SYS_OPEN, &param);
    } else {
        return INLINE_SYSCALL(open, 3, path, flags, mode);
    }
}

int open_manifest (const char ** argv)
{
    const char * manifest_name = *argv;
    int ret, fd;

    fd = sys_open(manifest_name, O_RDONLY, 0);
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
    memcpy((void *) manifest_name, *argv, len);
    memcpy((void *) manifest_name + len, ".manifest",
           static_strlen(".manifest"));

    fd = sys_open(manifest_name, O_RDONLY, 0);
    if (!IS_ERR(fd))
        return fd;

    /* find "manifest" file */
    fd = sys_open("manifest", O_RDONLY, 0);
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

/* This is the hashing function specified by the ELF ABI.  In the
   first five operations no overflow is possible so we optimized it a
   bit.  */
unsigned long int elf_hash (const char *name_arg)
{
    const unsigned char *name = (const unsigned char *) name_arg;
    unsigned long int hash = 0;

    if (*name == '\0')
        return hash;

    hash = *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    if (*name == '\0')
        return hash;

    hash = (hash << 4) + *name++;
    while (*name != '\0') {
        unsigned long int hi;
        hash = (hash << 4) + *name++;
        hi = hash & 0xf0000000;

        /*
         * The algorithm specified in the ELF ABI is as follows:
         * if (hi != 0)
         * hash ^= hi >> 24;
         * hash &= ~hi;
         * But the following is equivalent and a lot faster, especially on
         *  modern processors.
         */

        hash ^= hi;
        hash ^= hi >> 24;
    }
    return hash;
}

static void *
find_symbol (void * addr, ElfW(Word) * hashbuckets,
             ElfW(Word) hashsize, ElfW(Word) * hashchain,
             const ElfW(Sym) * symtab, const char * strtab,
             const char * name)
{
    unsigned long int hash = elf_hash(name);
    int len = strlen(name);

    /* Use the old SysV-style hash table.  Search the appropriate
       hash bucket in this object's symbol table for a definition
       for the same symbol name.  */
    for (ElfW(Word) symidx = hashbuckets[hash % hashsize];
         symidx != STN_UNDEF;
         symidx = hashchain[symidx]) {
        const ElfW(Sym) * sym = &symtab[symidx];
        if (!memcmp(strtab + sym->st_name, name, len + 1))
            return (void *) addr + sym->st_value;
    }

    return NULL;
}

static int load_static (const char * filename, void ** load_addr,
                        void ** entry, ElfW(Dyn) ** dyn,
                        unsigned long * phoff, int * phnum,
                        void ** code_start, void ** code_end,
                        ElfW(Word) ** hashbuckets,
                        ElfW(Word) * hashsize, ElfW(Word) ** hashchain,
                        ElfW(Sym) ** symtab, const char ** strtab)
{
    int ret = 0;

    int fd = sys_open(filename, O_RDONLY|O_CLOEXEC, 0);
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
    ElfW(Dyn) * dynamic = NULL;
    ElfW(Addr) base = (ElfW(Addr)) *load_addr;

    *phoff = header->e_phoff;
    *phnum = header->e_phnum;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend, dataend, allocend;
        off_t mapoff;
        int prot;
    } loadcmds[16], *c, *text_loadcmd = NULL;
    int nloadcmds = 0;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        switch (ph->p_type) {
            case PT_DYNAMIC:
                dynamic = (void *) ph->p_vaddr;
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
                if (ph->p_flags & PF_X)
                    text_loadcmd = c;
                break;
        }

    c = loadcmds;
    int maplength = loadcmds[nloadcmds - 1].allocend - c->mapstart;

    base = INLINE_SYSCALL(mmap, 6, base, maplength, c->prot,
                          (base ? MAP_FIXED : 0) | MAP_PRIVATE | MAP_FILE,
                          fd, c->mapoff);

    if (IS_ERR(base)) {
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
            INLINE_SYSCALL(mprotect, 3, base + c->mapend, maplength -
                           c->mapend, PROT_NONE);

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

    dynamic = (void *) (base + (ElfW(Addr)) dynamic);

    for (const ElfW(Dyn) * d = dynamic ; d->d_tag != DT_NULL ; d++)
        switch (d->d_tag) {
            case DT_SYMTAB:
                *symtab = (void *) base + d->d_un.d_ptr;
                break;
            case DT_STRTAB:
                *strtab = (void *) base + d->d_un.d_ptr;
                break;
            case DT_HASH: {
                ElfW(Word) * hash = (void *) base + d->d_un.d_ptr;
                /* Structure of DT_HASH:
                     The bucket array forms the hast table itself.
                     The entries in the chain array parallel the
                     symbol table.
                     [        nbucket        ]
                     [        nchain         ]
                     [       bucket[0]       ]
                     [          ...          ]
                     [   bucket[nbucket-1]   ]
                     [       chain[0]        ]
                     [          ...          ]
                     [    chain[nchain-1]    ] */

                *hashsize = *hash++;
                hash++;
                *hashbuckets = hash;
                hash += *hashsize;
                *hashchain = hash;
                break;
            }
        }

    *dyn = dynamic;
    *load_addr  = (void *) base;
    *entry      = (void *) base + header->e_entry;
    *code_start = (void *) base + text_loadcmd->mapstart;
    *code_end   = (void *) base + text_loadcmd->mapend;
out:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

#ifdef DEBUG
void __attribute__((noinline)) _dl_debug_state (void) {}

struct link_map {
    ElfW(Addr)        l_addr;
    const char *      l_name;
    const ElfW(Dyn) * l_ld;
    struct link_map * l_next, * l_prev;
};

static struct link_map init_link_map;

struct r_debug _r_debug =
    { 1, NULL, (ElfW(Addr)) &_dl_debug_state, RT_CONSISTENT, 0 };
#endif

int ioctl_set_graphene (int device, struct config_store * sandbox_config, int npolices,
                        const struct graphene_user_policy * policies);

int set_sandbox (int device, struct config_store * sandbox_config,
                 struct pal_sec * pal_sec_addr, void * pal_addr)
{
    struct graphene_user_policy policies[] = {
        { .type  = GRAPHENE_UNIX_PREFIX,
          .value = &pal_sec_addr->pipe_prefix, },
        { .type  = GRAPHENE_MCAST_PORT,
          .value = &pal_sec_addr->mcast_port, },
        { .type  = GRAPHENE_FS_PATH | GRAPHENE_FS_READ,
          .value = "/proc/meminfo", },
    };

    return ioctl_set_graphene(device, sandbox_config,
                              sizeof(policies) / sizeof(policies[0]),
                              policies);
}

int install_initial_syscall_filter (int has_reference_monitor);
int install_syscall_filter (void * pal_code_start, void * pal_code_end);

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
    int argc;
    const char ** argv, ** envp;
    ElfW(auxv_t) * auxv;
    pid_t pid;
    bool do_sandbox = false;
    int ret = 0;

    do_bootstrap(args, &argc, &argv, &envp, &auxv);

    /* VERY IMPORTANT: This is the filter that gets applied to the startup code
     * before applying the real filter in the function install_syscall_filter.
     * If you face any issues, you may have to enable certain syscalls here to
     * successfully make changes to startup code. */

    struct pal_sec * __pal_sec = __alloca(sizeof(struct pal_sec));

    ret = INLINE_SYSCALL(read, 3, PROC_INIT_FD, __pal_sec,
                         sizeof(struct pal_sec));

    if (IS_ERR(ret)) {
        if (ERRNO(ret) != EBADF)
            goto exit;

        for (const char ** env = envp ; *env ; env++) {
            /* check if "SANDBOX=1" is specified in the environment variables */
            const char * e = *env;
            if (strequal_static(e, "SANDBOX=1")) {
                do_sandbox = true;
                break;
            }
        }

        /* occupy PAL_INIT_FD */
        INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);
        __pal_sec = NULL;

        if (do_sandbox) {
            /* open the ioctl device of reference monitor */
            ret = INLINE_SYSCALL(open, 2, GRM_FILE, O_RDONLY);
            if (ret < 0) {
                printf("Unable to open the ioctl device of reference monitor\n");
                goto exit;
            } else {
                reference_monitor = ret;
            }
        }

        /* get the pid before it closes */
        pid = INLINE_SYSCALL(getpid, 0);

        ret = install_initial_syscall_filter((reference_monitor > 0));
        if (ret < 0) {
            printf("Unable to install initial system call filter\n");
            goto exit;
        }
    } else {
        if (ret != sizeof(struct pal_sec)) {
            ret = -EINVAL;
            goto exit;
        }

        pid = __pal_sec->process_id;
        reference_monitor = __pal_sec->reference_monitor;
        do_sandbox = (reference_monitor != 0);
    }

#ifdef DEBUG
    init_link_map.l_addr = (ElfW(Addr)) TEXT_START;
    init_link_map.l_ld = NULL;
    init_link_map.l_name = argv[0];

    _r_debug.r_state = RT_ADD;
    _dl_debug_state();

    _r_debug.r_map = &init_link_map;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state();
#endif

    void *        pal_addr  = NULL;
    void *        pal_entry = NULL;
    ElfW(Dyn) *   pal_dyn   = NULL;
    unsigned long pal_phoff = 0;
    int           pal_phnum = 0;
    void *        pal_code_start  = NULL;
    void *        pal_code_end    = NULL;
    ElfW(Word) *  pal_hashbuckets = NULL;
    ElfW(Word)    pal_hashsize    = 0;
    ElfW(Word) *  pal_hashchain   = NULL;
    ElfW(Sym) *   pal_symtab = NULL;
    const char *  pal_strtab = NULL;

    /* if the current process is a child, load PAL at the exactly
       same address as in the parent */
    if (__pal_sec)
        pal_addr = __pal_sec->load_address;

    ret = load_static(PAL_LOADER, &pal_addr, &pal_entry, &pal_dyn,
                      &pal_phoff, &pal_phnum,
                      &pal_code_start, &pal_code_end,
                      &pal_hashbuckets, &pal_hashsize,
                      &pal_hashchain,
                      &pal_symtab, &pal_strtab);

    if (ret < 0) {
        printf("Unable to load PAL loader\n");
        goto exit;
    }

    struct pal_sec * pal_sec_addr =
            find_symbol(pal_addr, pal_hashbuckets, pal_hashsize,
                        pal_hashchain, pal_symtab, pal_strtab,
                        "pal_sec");
    if (!pal_sec_addr) {
        printf("Unable to find 'pal_sec' in PAL loader\n");
        goto exit;
    }

    if (__pal_sec) {
        memcpy(pal_sec_addr, __pal_sec, sizeof(struct pal_sec));
        goto done_child;
    }

    int rand_gen = sys_open(RANDGEN_DEVICE, O_RDONLY, 0);
    if (IS_ERR(rand_gen)) {
        printf("Unable to open random generator device\n");
        goto exit;
    }

    unsigned short mcast_port = 0;
    ret = INLINE_SYSCALL(read, 3, rand_gen, &mcast_port, sizeof(mcast_port));
    if (IS_ERR(ret)) {
        ret = -ERRNO(ret);
        goto exit;
    }

    pal_sec_addr->reference_monitor = reference_monitor;
    pal_sec_addr->load_address    = pal_addr;
    pal_sec_addr->process_id      = pid;
    pal_sec_addr->random_device   = rand_gen;
    pal_sec_addr->mcast_port      = mcast_port % (65536 - 1024) + 1024;

    /* if "SANDBOX=1" if given, initiate the reference monitor */
    if (do_sandbox) {
        int manifest;
        if (!argc || (manifest = open_manifest(argv + 1)) < 0) {
            printf("USAGE: %s [executable|manifest] args ...\n", "pal-sec");
            goto exit;
        }

        struct config_store sandbox_config;
        ret = load_manifest(manifest, &sandbox_config);
        if (ret < 0)
            goto exit;


        ret = set_sandbox(reference_monitor, &sandbox_config,
                          pal_sec_addr, pal_addr);
        if (ret < 0) {
            printf("Unable to load sandbox policies\n");
            goto exit;
        }
    }

    ret = install_syscall_filter(pal_code_start, pal_code_end);
    if (ret < 0) {
        printf("Unable to install system call filter\n");
        goto exit;
    }

    /* free PAL_INIT_FD */
    INLINE_SYSCALL(close, 1, PROC_INIT_FD);

done_child:

#ifdef DEBUG
    pal_sec_addr->r_debug_addr = &_r_debug;
    pal_sec_addr->dl_debug_state_addr = &_dl_debug_state;

    struct link_map * pal_map = malloc(sizeof(struct link_map));
    pal_map->l_name = PAL_LOADER;
    pal_map->l_addr = (ElfW(Addr)) pal_addr;
    pal_map->l_ld   = pal_dyn;

    _r_debug.r_state = RT_ADD;
    _dl_debug_state();

    init_link_map.l_next = pal_map;
    pal_map->l_prev = &init_link_map;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state();
#endif

    /* just hand the original stack to the PAL loader */
    for (ElfW(auxv_t) * av = auxv ; av->a_type != AT_NULL ; av++)
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
                  :: "r"(args), "r"(pal_entry) : "memory");

    /* should never return */

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

