/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_rtld.h>
#include "sgx_internal.h"
#include "sgx_tls.h"
#include "sgx_enclave.h"
#include "debugger/sgx_gdb.h"

#include <asm/fcntl.h>
#include <asm/socket.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <asm/errno.h>

#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>

#define ENCLAVE_FILENAME RUNTIME_FILE("libpal-Linux-SGX.so")

unsigned long pagesize  = PRESET_PAGESIZE;
unsigned long pagemask  = ~(PRESET_PAGESIZE - 1);
unsigned long pageshift = PRESET_PAGESIZE - 1;

static inline
const char * alloc_concat(const char * p, int plen,
                          const char * s, int slen)
{
    plen = (plen != -1) ? plen : (p ? strlen(p) : 0);
    slen = (slen != -1) ? slen : (s ? strlen(s) : 0);

    char * buf = malloc(plen + slen + 1);
    if (plen)
        memcpy(buf, p, plen);
    if (slen)
        memcpy(buf + plen, s, slen);

    buf[plen + slen] = '\0';
    return buf;
}

static unsigned long parse_int (const char * str)
{
    unsigned long num = 0;
    int radix = 10;
    char c;

    if (str[0] == '0') {
        str++;
        radix = 8;
        if (str[0] == 'x') {
            str++;
            radix = 16;
        }
    }

    while ((c = *(str++))) {
        int val;
        if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= '0' && c <= '9')
            val = c - '0';
        else
            break;
        if (val >= radix)
            break;
        num = num * radix + val;
    }

    if (c == 'G' || c == 'g')
        num *= 1024 * 1024 * 1024;
    else if (c == 'M' || c == 'm')
        num *= 1024 * 1024;
    else if (c == 'K' || c == 'k')
        num *= 1024;

    return num;
}

static const char * resolve_uri (const char * uri, const char ** errstring)
{
    if (!strpartcmp_static(uri, "file:")) {
        *errstring = "Invalid URI";
        return NULL;
    }

    char path_buf[URI_MAX];
    int len = get_norm_path(uri + 5, path_buf, 0, URI_MAX);
    if (len < 0) {
        *errstring = "Invalid URI";
        return NULL;
    }

    return alloc_concat("file:", static_strlen("file:"), path_buf, len);
}

static
int scan_enclave_binary (int fd, unsigned long * base, unsigned long * size,
                         unsigned long * entry)
{
    int ret = 0;

    if (IS_ERR(ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET)))
        return -ERRNO(ret);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    const ElfW(Ehdr) * header = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + header->e_phoff;
    const ElfW(Phdr) * ph;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16)
                return -EINVAL;

            c = &loadcmds[nloadcmds++];
            c->mapstart = ALLOC_ALIGNDOWN(ph->p_vaddr);
            c->mapend = ALLOC_ALIGNUP(ph->p_vaddr + ph->p_memsz);
        }

    *base = loadcmds[0].mapstart;
    *size = loadcmds[nloadcmds - 1].mapend - loadcmds[0].mapstart;
    if (entry)
        *entry = header->e_entry;
    return 0;
}

static
int load_enclave_binary (sgx_arch_secs_t * secs, int fd,
                         unsigned long base, unsigned long prot)
{
    int ret = 0;

    if (IS_ERR(ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET)))
        return -ERRNO(ret);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    const ElfW(Ehdr) * header = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + header->e_phoff;
    const ElfW(Phdr) * ph;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend, datastart, dataend, allocend;
        unsigned int mapoff;
        int prot;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16)
                return -EINVAL;

            c = &loadcmds[nloadcmds++];
            c->mapstart = ALLOC_ALIGNDOWN(ph->p_vaddr);
            c->mapend = ALLOC_ALIGNUP(ph->p_vaddr + ph->p_filesz);
            c->datastart = ph->p_vaddr;
            c->dataend = ph->p_vaddr + ph->p_filesz;
            c->allocend = ph->p_vaddr + ph->p_memsz;
            c->mapoff = ALLOC_ALIGNDOWN(ph->p_offset);
            c->prot = (ph->p_flags & PF_R ? PROT_READ  : 0)|
                      (ph->p_flags & PF_W ? PROT_WRITE : 0)|
                      (ph->p_flags & PF_X ? PROT_EXEC  : 0)|prot;
        }

    base -= loadcmds[0].mapstart;
    for (c = loadcmds; c < &loadcmds[nloadcmds] ; c++) {
        ElfW(Addr) zero = c->dataend;
        ElfW(Addr) zeroend = ALLOC_ALIGNUP(c->allocend);
        ElfW(Addr) zeropage = ALLOC_ALIGNUP(zero);

        if (zeroend < zeropage)
            zeropage = zeroend;

        if (c->mapend > c->mapstart) {
            void * addr = (void *) INLINE_SYSCALL(mmap, 6, NULL,
                                                  c->mapend - c->mapstart,
                                                  PROT_READ|PROT_WRITE,
                                                  MAP_PRIVATE | MAP_FILE,
                                                  fd, c->mapoff);

            if (IS_ERR_P(addr))
                return -ERRNO_P(addr);

            if (c->datastart > c->mapstart)
                memset(addr, 0, c->datastart - c->mapstart);

            if (zeropage > zero)
                memset(addr + zero - c->mapstart, 0, zeropage - zero);

            ret = add_pages_to_enclave(secs, (void *) base + c->mapstart, addr,
                                       c->mapend - c->mapstart,
                                       SGX_PAGE_REG, c->prot, 0,
                                       (c->prot & PROT_EXEC) ? "code" : "data");

            INLINE_SYSCALL(munmap, 2, addr, c->mapend - c->mapstart);

            if (ret < 0)
                return ret;
        }

        if (zeroend > zeropage) {
            ret = add_pages_to_enclave(secs, (void *) base + zeropage, NULL,
                                       zeroend - zeropage,
                                       SGX_PAGE_REG, c->prot, 1, "bss");
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

int initialize_enclave (struct pal_enclave * enclave)
{
    int ret = 0;

    int                  enclave_image;
    int                  enclave_thread_num = 1;
    sgx_arch_token_t     enclave_token;
    sgx_arch_sigstruct_t enclave_sigstruct;
    sgx_arch_secs_t      enclave_secs;
    unsigned long        enclave_entry_addr;
    void *               tcs_addrs[MAX_DBG_THREADS];
    unsigned long        heap_min = DEAFULT_HEAP_MIN;

#define TRY(func, ...)                                              \
    ({                                                              \
        ret = func(__VA_ARGS__);                                    \
        if (ret < 0) {                                              \
            SGX_DBG(DBG_E, "initializing enclave failed: " #func ": %d\n",  \
                   -ret);                                           \
            goto err;                                               \
        } ret;                                                      \
    })

    enclave_image = INLINE_SYSCALL(open, 3, ENCLAVE_FILENAME, O_RDONLY, 0);
    if (IS_ERR(enclave_image)) {
        SGX_DBG(DBG_E, "cannot find %s\n", ENCLAVE_FILENAME);
        ret = -ERRNO(ret);
        goto err;
    }

    char cfgbuf[CONFIG_MAX];

    /* Reading sgx.enclave_size from manifest */
    if (get_config(enclave->config, "sgx.enclave_size", cfgbuf, CONFIG_MAX) <= 0) {
        SGX_DBG(DBG_E, "enclave_size is not specified\n");
        ret = -EINVAL;
        goto err;
    }

    enclave->size = parse_int(cfgbuf);

    /* DEP 1/21/17: SGX currently only supports power-of-two enclaves.
     * Give users a better warning about this. */
    if (enclave->size & (enclave->size - 1)) {
        SGX_DBG(DBG_E, "Enclave size not a power of two.  SGX requires power-of-two enclaves.\n");
        ret = -EINVAL;
        goto err;
    }

    /* Reading sgx.thread_num from manifest */
    if (get_config(enclave->config, "sgx.thread_num", cfgbuf, CONFIG_MAX) > 0)
        enclave->thread_num = parse_int(cfgbuf);

    if (enclave_thread_num > MAX_DBG_THREADS) {
        SGX_DBG(DBG_E, "Too many threads to debug\n");
        ret = -EINVAL;
        goto err;
    }

    /* Reading sgx.static_address from manifest */
    if (get_config(enclave->config, "sgx.static_address", cfgbuf, CONFIG_MAX) > 0 &&
        cfgbuf[0] == '1')
        enclave->baseaddr = heap_min;
    else
        enclave->baseaddr = heap_min = 0;

    TRY(read_enclave_token, enclave->token, &enclave_token);
    TRY(read_enclave_sigstruct, enclave->sigfile, &enclave_sigstruct);

    TRY(create_enclave,
        &enclave_secs, enclave->baseaddr, enclave->size, &enclave_token);

    enclave->baseaddr = enclave_secs.baseaddr;
    enclave->size = enclave_secs.size;
    enclave->ssaframesize = enclave_secs.ssaframesize * pagesize;

    struct stat stat;
    ret = INLINE_SYSCALL(fstat, 2, enclave->manifest, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);
    int manifest_size = stat.st_size;

    /* Start populating enclave memory */
    struct mem_area {
        const char * desc;
        bool skip_eextend;
        bool is_binary;
        int fd;
        unsigned long addr, size, prot;
        enum sgx_page_type type;
    };

    struct mem_area * areas =
        __alloca(sizeof(areas[0]) * (10 + enclave->thread_num));
    int area_num = 0;

#define set_area(_desc, _skip_eextend, _is_binary, _fd, _addr, _size, _prot, _type)\
    ({                                                                  \
        struct mem_area * _a = &areas[area_num++];                      \
        _a->desc = _desc; _a->skip_eextend = _skip_eextend;             \
        _a->is_binary = _is_binary;                                     \
        _a->fd = _fd; _a->addr = _addr; _a->size = _size;               \
        _a->prot = _prot; _a->type = _type; _a;                         \
    })

    struct mem_area * manifest_area =
        set_area("manifest", false, false, enclave->manifest,
                 0, ALLOC_ALIGNUP(manifest_size),
                 PROT_READ, SGX_PAGE_REG);
    struct mem_area * ssa_area =
        set_area("ssa", true, false, -1, 0,
                 enclave->thread_num * enclave->ssaframesize * SSAFRAMENUM,
                 PROT_READ|PROT_WRITE, SGX_PAGE_REG);
    /* XXX: TCS should be part of measurement */
    struct mem_area * tcs_area =
        set_area("tcs", true, false, -1, 0, enclave->thread_num * pagesize,
                 0, SGX_PAGE_TCS);
    /* XXX: TLS should be part of measurement */
    struct mem_area * tls_area =
        set_area("tls", true, false, -1, 0, enclave->thread_num * pagesize,
                 PROT_READ|PROT_WRITE, SGX_PAGE_REG);

    /* XXX: the enclave stack should be part of measurement */
    struct mem_area * stack_areas = &areas[area_num];
    for (int t = 0 ; t < enclave->thread_num ; t++)
        set_area("stack", true, false, -1, 0, ENCLAVE_STACK_SIZE,
                 PROT_READ|PROT_WRITE, SGX_PAGE_REG);

    struct mem_area * pal_area =
        set_area("pal", false, true, enclave_image, 0, 0, 0, SGX_PAGE_REG);
    TRY(scan_enclave_binary,
        enclave_image, &pal_area->addr, &pal_area->size, &enclave_entry_addr);

    struct mem_area * exec_area = NULL;
    if (enclave->exec != -1) {
        exec_area = set_area("exec", false, true, enclave->exec, 0, 0,
                             PROT_WRITE, SGX_PAGE_REG);
        TRY(scan_enclave_binary,
            enclave->exec, &exec_area->addr, &exec_area->size, NULL);
    }

    unsigned long populating = enclave->size;
    for (int i = 0 ; i < area_num ; i++) {
        if (areas[i].addr)
            continue;
        areas[i].addr = populating - areas[i].size;
        if (&areas[i] == exec_area)
            populating = areas[i].addr;
        else
            populating = areas[i].addr - MEMORY_GAP;
    }

    enclave_entry_addr += pal_area->addr;

    if (exec_area) {
        if (exec_area->addr + exec_area->size > pal_area->addr)
            return -EINVAL;

        if (exec_area->addr + exec_area->size < populating) {
            if (populating > heap_min) {
                unsigned long addr = exec_area->addr + exec_area->size;
                if (addr < heap_min)
                    addr = heap_min;
                set_area("free", true, false, -1, addr, populating - addr,
                         PROT_READ|PROT_WRITE|PROT_EXEC, SGX_PAGE_REG);
            }

            populating = exec_area->addr;
        }
    }

    if (populating > heap_min) {
        set_area("free", true, false, -1, heap_min, populating - heap_min,
                 PROT_READ|PROT_WRITE|PROT_EXEC, SGX_PAGE_REG);
    }

    for (int i = 0 ; i < area_num ; i++) {
        if (areas[i].fd != -1 && areas[i].is_binary) {
            TRY(load_enclave_binary,
                &enclave_secs, areas[i].fd, areas[i].addr, areas[i].prot);
            continue;
        }

        void * data = NULL;

        if (strcmp_static(areas[i].desc, "tls")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANON|MAP_PRIVATE, -1, 0);

            for (int t = 0 ; t < enclave->thread_num ; t++) {
                struct enclave_tls * gs = data + pagesize * t;
                gs->enclave_size = enclave->size;
                gs->tcs_offset = tcs_area->addr + pagesize * t;
                gs->initial_stack_offset =
                    stack_areas[t].addr + ENCLAVE_STACK_SIZE;
                gs->ssa = (void *) ssa_area->addr +
                    enclave->ssaframesize * SSAFRAMENUM * t +
                    enclave_secs.baseaddr;
                gs->gpr = gs->ssa +
                    enclave->ssaframesize - sizeof(sgx_arch_gpr_t);
            }

            goto add_pages;
        }

        if (strcmp_static(areas[i].desc, "tcs")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANON|MAP_PRIVATE, -1, 0);

            for (int t = 0 ; t < enclave->thread_num ; t++) {
                sgx_arch_tcs_t * tcs = data + pagesize * t;
                memset(tcs, 0, pagesize);
                tcs->ossa = ssa_area->addr +
                    enclave->ssaframesize * SSAFRAMENUM * t;
                tcs->nssa = SSAFRAMENUM;
                tcs->oentry = enclave_entry_addr;
                tcs->ofsbasgx = 0;
                tcs->ogsbasgx = tls_area->addr + t * pagesize;
                tcs->fslimit = 0xfff;
                tcs->gslimit = 0xfff;
                tcs_addrs[t] = (void *) enclave_secs.baseaddr + tcs_area->addr
                    + pagesize * t;
            }

            goto add_pages;
        }

        if (areas[i].fd != -1)
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ,
                                           MAP_FILE|MAP_PRIVATE,
                                           areas[i].fd, 0);

add_pages:
        TRY(add_pages_to_enclave,
            &enclave_secs, (void *) areas[i].addr, data, areas[i].size,
            areas[i].type, areas[i].prot, areas[i].skip_eextend,
            areas[i].desc);

        if (data)
            INLINE_SYSCALL(munmap, 2, data, areas[i].size);
    }

    TRY(init_enclave, &enclave_secs, &enclave_sigstruct, &enclave_token);

    create_tcs_mapper((void *) enclave_secs.baseaddr + tcs_area->addr,
                      enclave->thread_num);

    struct pal_sec * pal_sec = &enclave->pal_sec;

    pal_sec->enclave_addr = (PAL_PTR) (enclave_secs.baseaddr + pal_area->addr);

    pal_sec->heap_min = (void *) enclave_secs.baseaddr + heap_min;
    pal_sec->heap_max = (void *) enclave_secs.baseaddr + pal_area->addr - MEMORY_GAP;

    if (exec_area) {
        pal_sec->exec_addr = (void *) enclave_secs.baseaddr + exec_area->addr;
        pal_sec->exec_size = exec_area->size;
    }

    pal_sec->manifest_addr = (void *) enclave_secs.baseaddr + manifest_area->addr;
    pal_sec->manifest_size = manifest_size;

    memcpy(pal_sec->mrenclave, enclave_secs.mrenclave,
           sizeof(sgx_arch_hash_t));
    memcpy(pal_sec->mrsigner, enclave_secs.mrsigner,
           sizeof(sgx_arch_hash_t));
    memcpy(&pal_sec->enclave_attributes, &enclave_secs.attributes,
           sizeof(sgx_arch_attributes_t));

    struct enclave_dbginfo * dbg = (void *)
            INLINE_SYSCALL(mmap, 6, DBGINFO_ADDR,
                           sizeof(struct enclave_dbginfo),
                           PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                           -1, 0);
    if (IS_ERR_P(dbg)) {
        SGX_DBG(DBG_E, "Cannot allocate debug info\n");
        return 0;
    }

    dbg->pid = INLINE_SYSCALL(getpid, 0);
    dbg->base = enclave->baseaddr;
    dbg->size = enclave->size;
    dbg->ssaframesize = enclave->ssaframesize;
    dbg->aep  = async_exit_pointer;
    dbg->thread_tids[0] = dbg->pid;
    for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
        dbg->tcs_addrs[i] = tcs_addrs[i];

    return 0;
err:
    return ret;
}

static int mcast_s (int port)
{
    struct sockaddr_in addr;
    int ret = 0;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    int fd = INLINE_SYSCALL(socket, 3, AF_INET, SOCK_DGRAM, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return fd;
}

static int mcast_c (int port)
{
    int ret = 0, fd;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    fd = INLINE_SYSCALL(socket, 3, AF_INET, SOCK_DGRAM, 0);
    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    int reuse = 1;
    INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

    ret = INLINE_SYSCALL(bind, 3, fd, &addr, sizeof(addr));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    inet_pton4(MCAST_GROUP, sizeof(MCAST_GROUP) - 1,
               &addr.sin_addr.s_addr);

    struct ip_mreq group;
    group.imr_multiaddr.s_addr = addr.sin_addr.s_addr;
    group.imr_interface.s_addr = INADDR_ANY;

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    return fd;
}

static unsigned long randval = 0;

void getrand (void * buffer, size_t size)
{
    size_t bytes = 0;

    while (bytes + sizeof(uint64_t) <= size) {
        *(uint64_t*) (buffer + bytes) = randval;
        randval = hash64(randval);
        bytes += sizeof(uint64_t);
    }

    if (bytes < size) {
        memcpy(buffer + bytes, &randval, size - bytes);
        randval = hash64(randval);
    }
}

static void create_instance (struct pal_sec * pal_sec)
{
    unsigned int id;
    getrand(&id, sizeof(id));
    snprintf(pal_sec->pipe_prefix, sizeof(pal_sec->pipe_prefix),
             "/graphene/%x/", id);
    pal_sec->instance_id = id;
}

int load_manifest (int fd, struct config_store ** config_ptr)
{
    int retval = -EINVAL;
    int nbytes = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_END);

    if (IS_ERR(nbytes))
        return -ERRNO(nbytes);

    struct config_store * config = malloc(sizeof(struct config_store));
    if (!config)
        return -ENOMEM;

    void * config_raw = (void *)
            INLINE_SYSCALL(mmap, 6, NULL, nbytes,
                           PROT_READ|PROT_WRITE, MAP_PRIVATE,
                           fd, 0);

    if (IS_ERR_P(config_raw)) {
        retval = -ERRNO_P(config_raw);
        goto finalize;
    }

    config->raw_data = config_raw;
    config->raw_size = nbytes;
    config->malloc   = malloc;
    config->free     = NULL;

    const char * errstring = NULL;
    int ret = read_config(config, NULL, &errstring);

    if (ret < 0) {
        SGX_DBG(DBG_E, "can't read manifest: %s\n", errstring);
        retval = ret;
        goto finalize;
    }

    *config_ptr = config;
    return 0;

finalize:
    if (config) {
        free(config);
    }
    if (!IS_ERR_P(config_raw)) {
        INLINE_SYSCALL(munmap, 2, config_raw, nbytes);
    }
    return retval;
}

static int load_enclave (struct pal_enclave * enclave,
                         const char * manifest_uri,
                         const char * exec_uri,
                         const char ** arguments, const char ** environments,
                         bool exec_uri_inferred)
{
    struct pal_sec * pal_sec = &enclave->pal_sec;
    int ret;
    const char * errstring;
    struct timeval tv;

#if PRINT_ENCLAVE_STAT == 1
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    pal_sec->start_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    ret = open_gsgx();
    if (ret < 0)
        return ret;

    if (!is_wrfsbase_supported())
        return -EPERM;

    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    randval = tv.tv_sec * 1000000UL + tv.tv_usec;

    pal_sec->pid = INLINE_SYSCALL(getpid, 0);
    pal_sec->uid = INLINE_SYSCALL(getuid, 0);
    pal_sec->gid = INLINE_SYSCALL(getgid, 0);

#ifdef DEBUG
    for (const char ** e = environments ; *e ; e++) {
        if (strcmp_static(*e, "IN_GDB=1")) {
            SGX_DBG(DBG_I, "being GDB'ed!!!\n");
            pal_sec->in_gdb = true;
        }

        if (strcmp_static(*e, "LD_PRELOAD="))
            *e = "\0";
    }
#endif

    char cfgbuf[CONFIG_MAX];

    enclave->manifest = INLINE_SYSCALL(open, 3, manifest_uri + 5,
                                       O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->manifest)) {
         SGX_DBG(DBG_E, "cannot open manifest %s\n", manifest_uri);
         return -EINVAL;
    }

    ret = load_manifest(enclave->manifest, &enclave->config);
    if (ret < 0) {
        SGX_DBG(DBG_E, "invalid manifest: %s\n", manifest_uri);
        return -EINVAL;
    }

    // A manifest can specify an executable with a different base name
    // than the manifest itself.  Always give the exec field of the manifest
    // precedence if specified.
    if (get_config(enclave->config, "loader.exec", cfgbuf, CONFIG_MAX) > 0) {
        exec_uri = resolve_uri(cfgbuf, &errstring);
        exec_uri_inferred = false;
        if (!exec_uri) {
            SGX_DBG(DBG_E, "%s: %s\n", errstring, cfgbuf);
            return -EINVAL;
        }
    }

    if (exec_uri) {
        enclave->exec = INLINE_SYSCALL(open, 3,
                                       exec_uri + static_strlen("file:"),
                                       O_RDONLY|O_CLOEXEC, 0);
        if (IS_ERR(enclave->exec)) {
            if (exec_uri_inferred) {
                // It is valid for an enclave not to have an executable.
                // We need to catch the case where we inferred the executable
                // from the manifest file name, but it doesn't exist, and let
                // the enclave go a bit further.  Go ahead and warn the user,
                // though.
                SGX_DBG(DBG_I, "Inferred executable cannot be opened: %s.  This may be ok, or may represent a manifest misconfiguration. This typically represents advanced usage, and if it is not what you intended, try setting the loader.exec field in the manifest.\n", exec_uri);
                enclave->exec = -1;
            } else {
                SGX_DBG(DBG_E, "cannot open executable %s\n", exec_uri);
                return -EINVAL;
            }
        }
    } else {
        enclave->exec = -1;
    }

    if (get_config(enclave->config, "sgx.sigfile", cfgbuf, CONFIG_MAX) < 0) {
        SGX_DBG(DBG_E, "sigstruct file not found. Must have \'sgx.sigfile\' in the manifest\n");
        return -EINVAL;
    }

    const char * uri = resolve_uri(cfgbuf, &errstring);
    if (!uri) {
        SGX_DBG(DBG_E, "%s: %s\n", errstring, cfgbuf);
        return -EINVAL;
    }

    if (!strcmp_static(uri + strlen(uri) - 4, ".sig")) {
        SGX_DBG(DBG_E, "Invalid sigstruct file URI as %s\n", cfgbuf);
        return -EINVAL;
    }

    enclave->sigfile = INLINE_SYSCALL(open, 3, uri + 5, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->sigfile)) {
        SGX_DBG(DBG_E, "cannot open sigstruct file %s\n", uri);
        return -EINVAL;
    }

    uri = alloc_concat(uri, strlen(uri) - 4, ".token", -1);
    enclave->token = INLINE_SYSCALL(open, 3, uri + 5, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->token)) {
        SGX_DBG(DBG_E, "cannot open token \'%s\'. Use \'"
                PAL_FILE("pal-sgx-get-token")
                "\' on the runtime host, or run \'make SGX_RUN=1\' "
                "in the Graphene source, to create the token file.\n",
                uri);
        return -EINVAL;
    }

    /* Initialize the enclave */
    ret = initialize_enclave(enclave);
    if (ret < 0)
        return ret;

    snprintf(pal_sec->enclave_image,  sizeof(PAL_SEC_STR), "%s",
             ENCLAVE_FILENAME);

    if (!pal_sec->instance_id)
        create_instance(&enclave->pal_sec);

    pal_sec->manifest_fd = enclave->manifest;
    memcpy(pal_sec->manifest_name, manifest_uri, strlen(manifest_uri) + 1);

    if (enclave->exec == -1) {
        pal_sec->exec_fd = PAL_IDX_POISON;
        memset(pal_sec->exec_name, 0, sizeof(PAL_SEC_STR));
    } else {
        pal_sec->exec_fd = enclave->exec;
        memcpy(pal_sec->exec_name, exec_uri, strlen(exec_uri) + 1);
    }

    if (!pal_sec->mcast_port) {
        unsigned short mcast_port;
        getrand(&mcast_port, sizeof(unsigned short));
        pal_sec->mcast_port = mcast_port > 1024 ? mcast_port : mcast_port + 1024;
    }

    if ((ret = mcast_s(pal_sec->mcast_port)) >= 0) {
        pal_sec->mcast_srv = ret;
        if ((ret = mcast_c(pal_sec->mcast_port)) >= 0) {
            pal_sec->mcast_cli = ret;
        } else {
            INLINE_SYSCALL(close, 1, pal_sec->mcast_srv);
            pal_sec->mcast_srv = 0;
        }
    }

    /* setup signal handling */
    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;

    current_enclave = enclave;
    map_tcs(INLINE_SYSCALL(gettid, 0));

    /* start running trusted PAL */
    ecall_enclave_start(arguments, environments);

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM exit_time = 0;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    exit_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    unmap_tcs();
    INLINE_SYSCALL(exit, 0);
    return 0;
}

int main (int argc, const char ** argv, const char ** envp)
{
    const char * manifest_uri = NULL;
    char * exec_uri = NULL;
    const char * pal_loader = argv[0];
    int retval = -EINVAL;
    bool exec_uri_inferred = false; // Handle the case where the exec uri is
                                    // inferred from the manifest name somewhat
                                    // differently
    argc--;
    argv++;

    struct pal_enclave * enclave = malloc(sizeof(struct pal_enclave));
    if (!enclave)
        return -ENOMEM;

    memset(enclave, 0, sizeof(struct pal_enclave));

    int is_child = sgx_init_child_process(&enclave->pal_sec);
    if (is_child < 0) {
        retval = is_child;
        goto finalize;
    }

    if (!is_child) {
        /* occupy PROC_INIT_FD so no one will use it */
        INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);

        if (!argc)
            goto usage;

        if (strcmp_static(argv[0], "file:")) {
            exec_uri = alloc_concat(argv[0], -1, NULL, -1);
        } else {
            exec_uri = alloc_concat("file:", -1, argv[0], -1);
        }
    } else {
        exec_uri = alloc_concat(enclave->pal_sec.exec_name, -1, NULL, -1);
    }

    int fd = INLINE_SYSCALL(open, 3, exec_uri + 5, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(fd)) {
        SGX_DBG(DBG_E, "Executable not found\n");
        SGX_DBG(DBG_E, "USAGE: <pal> [executable|manifest] args ...\n");
        retval = -ERRNO(fd);
        goto finalize;
    }

    char filebuf[4];
    /* check if the first argument is a executable. If it is, try finding
       all the possible manifest files */
    INLINE_SYSCALL(read, 3, fd, filebuf, 4);
    INLINE_SYSCALL(close, 1, fd);

    char sgx_manifest[URI_MAX];
    int len = get_base_name(exec_uri + static_strlen("file:"), sgx_manifest,
                            URI_MAX);
    if (len < 0) {
        retval = len;
        goto finalize;
    }

    if (strcmp_static(sgx_manifest + len - strlen(".manifest"), ".manifest")) {
        strcpy_static(sgx_manifest + len, ".sgx", URI_MAX - len);
    } else if (!strcmp_static(sgx_manifest + len - strlen(".manifest.sgx"),
                              ".manifest.sgx")) {
        strcpy_static(sgx_manifest + len, ".manifest.sgx", URI_MAX - len);
    }

    if (memcmp(filebuf, "\177ELF", 4)) {
        // In this case the manifest is given as the executable.  Set
        // manifest_uri to sgx_manifest (should be the same), and
        // and drop the .manifest* from exec_uri, so that the program
        // loads properly.
        manifest_uri = sgx_manifest;
        size_t exec_len = strlen(exec_uri);
        if (strcmp_static(exec_uri + exec_len - strlen(".manifest"), ".manifest")) {
            exec_uri[exec_len - strlen(".manifest")] = '\0';
            exec_uri_inferred = true;
        } else if (strcmp_static(exec_uri + exec_len - strlen(".manifest.sgx"), ".manifest.sgx")) {
            exec_uri[exec_len - strlen(".manifest.sgx")] = '\0';
            exec_uri_inferred = true;
        }
    }

    fd = INLINE_SYSCALL(open, 3, sgx_manifest, O_RDONLY|O_CLOEXEC, 0);
    if (!IS_ERR(fd)) {
        manifest_uri = alloc_concat("file:", static_strlen("file:"),
                                    sgx_manifest, -1);
        INLINE_SYSCALL(close, 1, fd);
    } else if (!manifest_uri) {
        SGX_DBG(DBG_E, "cannot open manifest file: %s\n", sgx_manifest);
        goto usage;
    }

    SGX_DBG(DBG_I, "manifest file: %s\n", manifest_uri);
    if (exec_uri)
        SGX_DBG(DBG_I, "executable file: %s\n", exec_uri);
    else
        SGX_DBG(DBG_I, "executable file not found\n");

    return load_enclave(enclave, manifest_uri, exec_uri, argv, envp, exec_uri_inferred);

usage:
    SGX_DBG(DBG_E, "USAGE: %s [executable|manifest] args ...\n", pal_loader);
    retval = -EINVAL;
    goto finalize;

finalize:
    if (enclave) {
        free(enclave);
    }
    return retval;
}

int pal_init_enclave (const char * manifest_uri,
                      const char * exec_uri,
                      const char ** arguments, const char ** environments)
{
    if (!manifest_uri)
        return -PAL_ERROR_INVAL;

    struct pal_enclave * enclave = malloc(sizeof(struct pal_enclave));
    if (!enclave)
        return -PAL_ERROR_NOMEM;

    memset(enclave, 0, sizeof(struct pal_enclave));

    return load_enclave(enclave, manifest_uri, exec_uri,
                        arguments, environments, 0);
}
