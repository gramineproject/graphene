#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_rtld.h>
#include <hex.h>

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
#include <ctype.h>

#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>

unsigned long pagesize  = PRESET_PAGESIZE;
unsigned long pagemask  = ~(PRESET_PAGESIZE - 1);
unsigned long pageshift = PRESET_PAGESIZE - 1;

static inline
char * alloc_concat(const char * p, size_t plen,
                    const char * s, size_t slen)
{
    plen = (plen != (size_t)-1) ? plen : (p ? strlen(p) : 0);
    slen = (slen != (size_t)-1) ? slen : (s ? strlen(s) : 0);

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
        int8_t val = hex2dec(c);
        if (val < 0)
            break;
        if ((uint8_t) val >= radix)
            break;
        num = num * radix + (uint8_t) val;
    }

    if (c == 'G' || c == 'g')
        num *= 1024 * 1024 * 1024;
    else if (c == 'M' || c == 'm')
        num *= 1024 * 1024;
    else if (c == 'K' || c == 'k')
        num *= 1024;

    return num;
}

static char * resolve_uri (const char * uri, const char ** errstring)
{
    if (!strpartcmp_static(uri, "file:")) {
        *errstring = "Invalid URI";
        return NULL;
    }

    char path_buf[URI_MAX];
    size_t len = URI_MAX;
    int ret = get_norm_path(uri + 5, path_buf, &len);
    if (ret < 0) {
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
                                       SGX_PAGE_REG, c->prot, false, "bss");
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

int initialize_enclave (struct pal_enclave * enclave)
{
    int ret = 0;

    int                  enclave_image = -1;
    int                  enclave_thread_num = 1;
    sgx_arch_token_t     enclave_token;
    sgx_arch_sigstruct_t enclave_sigstruct;
    sgx_arch_secs_t      enclave_secs;
    unsigned long        enclave_entry_addr;
    void *               tcs_addrs[MAX_DBG_THREADS];
    unsigned long        heap_min = DEFAULT_HEAP_MIN;

    enclave_image = INLINE_SYSCALL(open, 3, ENCLAVE_FILENAME, O_RDONLY, 0);
    if (IS_ERR(enclave_image)) {
        SGX_DBG(DBG_E, "Cannot find %s\n", ENCLAVE_FILENAME);
        ret = -ERRNO(enclave_image);
        goto out;
    }

    char cfgbuf[CONFIG_MAX];

    /* Reading sgx.enclave_size from manifest */
    if (get_config(enclave->config, "sgx.enclave_size", cfgbuf, CONFIG_MAX) <= 0) {
        SGX_DBG(DBG_E, "Enclave size is not specified\n");
        ret = -EINVAL;
        goto out;
    }

    enclave->size = parse_int(cfgbuf);
    if (enclave->size & (enclave->size - 1)) {
        SGX_DBG(DBG_E, "Enclave size not a power of two (an SGX-imposed requirement)\n");
        ret = -EINVAL;
        goto out;
    }

    /* Reading sgx.thread_num from manifest */
    if (get_config(enclave->config, "sgx.thread_num", cfgbuf, CONFIG_MAX) > 0)
        enclave->thread_num = parse_int(cfgbuf);

    if (enclave_thread_num > MAX_DBG_THREADS) {
        SGX_DBG(DBG_E, "Too many threads to debug\n");
        ret = -EINVAL;
        goto out;
    }

    /* Reading sgx.static_address from manifest */
    if (get_config(enclave->config, "sgx.static_address", cfgbuf, CONFIG_MAX) > 0 && cfgbuf[0] == '1')
        enclave->baseaddr = heap_min;
    else
        enclave->baseaddr = heap_min = 0;

    ret = read_enclave_token(enclave->token, &enclave_token);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Reading enclave token failed: %d\n", -ret);
        goto out;
    }

    ret = read_enclave_sigstruct(enclave->sigfile, &enclave_sigstruct);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Reading enclave sigstruct failed: %d\n", -ret);
        goto out;
    }

    ret = create_enclave(&enclave_secs, enclave->baseaddr, enclave->size, &enclave_token);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Creating enclave failed: %d\n", -ret);
        goto out;
    }

    enclave->baseaddr = enclave_secs.baseaddr;
    enclave->size = enclave_secs.size;
    enclave->ssaframesize = enclave_secs.ssaframesize * pagesize;

    struct stat stat;
    ret = INLINE_SYSCALL(fstat, 2, enclave->manifest, &stat);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "Reading manifest file's size failed: %d\n", -ret);
        ret = -ERRNO(ret);
        goto out;
    }
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

    /* The manifest needs to be allocated at the upper end of the enclave
     * memory. That's used by pal_linux_main to find the manifest area. So add
     * it first to the list with memory areas. */
    areas[area_num] = (struct mem_area) {
        .desc = "manifest", .skip_eextend = false, .is_binary = false,
        .fd = enclave->manifest, .addr = 0, .size = ALLOC_ALIGNUP(manifest_size),
        .prot = PROT_READ, .type = SGX_PAGE_REG
    };
    area_num++;

    areas[area_num] = (struct mem_area) {
        .desc = "ssa", .skip_eextend = false, .is_binary = false,
        .fd = -1, .addr = 0, .size = enclave->thread_num * enclave->ssaframesize * SSAFRAMENUM,
        .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
    };
    struct mem_area* ssa_area = &areas[area_num++];

    areas[area_num] = (struct mem_area) {
        .desc = "tcs", .skip_eextend = false, .is_binary = false,
        .fd = -1, .addr = 0, .size = enclave->thread_num * pagesize,
        .prot = 0, .type = SGX_PAGE_TCS
    };
    struct mem_area* tcs_area = &areas[area_num++];

    areas[area_num] = (struct mem_area) {
        .desc = "tls", .skip_eextend = false, .is_binary = false,
        .fd = -1, .addr = 0, .size = enclave->thread_num * pagesize,
        .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
    };
    struct mem_area* tls_area = &areas[area_num++];

    struct mem_area* stack_areas = &areas[area_num]; /* memorize for later use */
    for (uint32_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area) {
            .desc = "stack", .skip_eextend = false, .is_binary = false,
            .fd = -1, .addr = 0, .size = ENCLAVE_STACK_SIZE,
            .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
        };
        area_num++;
    }

    areas[area_num] = (struct mem_area) {
        .desc = "pal", .skip_eextend = false, .is_binary = true,
        .fd = enclave_image, .addr = 0, .size = 0 /* set below */,
        .prot = 0, .type = SGX_PAGE_REG
    };
    struct mem_area* pal_area = &areas[area_num++];

    ret = scan_enclave_binary(enclave_image, &pal_area->addr, &pal_area->size, &enclave_entry_addr);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Scanning Pal binary (%s) failed: %d\n", ENCLAVE_FILENAME, -ret);
        goto out;
    }

    struct mem_area* exec_area = NULL;
    if (enclave->exec != -1) {
        areas[area_num] = (struct mem_area) {
            .desc = "exec", .skip_eextend = false, .is_binary = true,
            .fd = enclave->exec, .addr = 0, .size = 0 /* set below */,
            .prot = PROT_WRITE, .type = SGX_PAGE_REG
        };
        exec_area = &areas[area_num++];

        ret = scan_enclave_binary(enclave->exec, &exec_area->addr, &exec_area->size, NULL);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Scanning application binary failed: %d\n", -ret);
            goto out;
        }
    }

    unsigned long populating = enclave->size;
    for (int i = 0 ; i < area_num ; i++) {
        if (areas[i].addr)
            continue;
        areas[i].addr = populating - areas[i].size;
        populating = SATURATED_P_SUB(areas[i].addr, MEMORY_GAP, 0);
    }

    enclave_entry_addr += pal_area->addr;

    if (exec_area) {
        if (exec_area->addr + exec_area->size > pal_area->addr) {
            SGX_DBG(DBG_E, "Application binary overlaps with Pal binary\n");
            ret = -EINVAL;
            goto out;
        }

        if (exec_area->addr + exec_area->size + MEMORY_GAP < populating) {
            if (populating > heap_min) {
                unsigned long addr = exec_area->addr + exec_area->size + MEMORY_GAP;
                if (addr < heap_min)
                    addr = heap_min;

                areas[area_num] = (struct mem_area) {
                    .desc = "free", .skip_eextend = true, .is_binary = false,
                    .fd = -1, .addr = addr, .size = populating - addr,
                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC, .type = SGX_PAGE_REG
                };
                area_num++;
            }

            populating = SATURATED_P_SUB(exec_area->addr, MEMORY_GAP, 0);
        }
    }

    if (populating > heap_min) {
        areas[area_num] = (struct mem_area) {
            .desc = "free", .skip_eextend = true, .is_binary = false,
            .fd = -1, .addr = heap_min, .size = populating - heap_min,
            .prot = PROT_READ | PROT_WRITE | PROT_EXEC, .type = SGX_PAGE_REG
        };
        area_num++;
    }

    for (int i = 0 ; i < area_num ; i++) {
        if (areas[i].fd != -1 && areas[i].is_binary) {
            ret = load_enclave_binary(&enclave_secs, areas[i].fd, areas[i].addr, areas[i].prot);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Loading enclave binary failed: %d\n", -ret);
                goto out;
            }
            continue;
        }

        void * data = NULL;

        if (strcmp_static(areas[i].desc, "tls")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
            if (data == (void *)-1 || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tls pages failed\n");
                goto out;
            }

            for (uint32_t t = 0 ; t < enclave->thread_num ; t++) {
                struct enclave_tls * gs = data + pagesize * t;
                memset(gs, 0, pagesize);
                assert(sizeof(*gs) <= pagesize);
                gs->common.self = (PAL_TCB *)(
                    tls_area->addr + pagesize * t + enclave_secs.baseaddr);
                gs->enclave_size = enclave->size;
                gs->tcs_offset = tcs_area->addr + pagesize * t;
                gs->initial_stack_offset =
                    stack_areas[t].addr + ENCLAVE_STACK_SIZE;
                gs->ssa = (void *) ssa_area->addr +
                    enclave->ssaframesize * SSAFRAMENUM * t +
                    enclave_secs.baseaddr;
                gs->gpr = gs->ssa +
                    enclave->ssaframesize - sizeof(sgx_arch_gpr_t);
                gs->manifest_size = manifest_size;
                gs->heap_min = (void *) enclave_secs.baseaddr + heap_min;
                gs->heap_max = (void *) enclave_secs.baseaddr + pal_area->addr - MEMORY_GAP;
                if (exec_area) {
                    gs->exec_addr = (void *) enclave_secs.baseaddr + exec_area->addr;
                    gs->exec_size = exec_area->size;
                }
                gs->thread = NULL;
            }
        } else if (strcmp_static(areas[i].desc, "tcs")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
            if (data == (void *)-1 || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tcs pages failed\n");
                goto out;
            }

            for (uint32_t t = 0 ; t < enclave->thread_num ; t++) {
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
        } else if (areas[i].fd != -1) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ,
                                           MAP_FILE|MAP_PRIVATE,
                                           areas[i].fd, 0);
            if (data == (void *)-1 || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for file %s failed\n", areas[i].desc);
                goto out;
            }
        }

        ret = add_pages_to_enclave(&enclave_secs, (void *) areas[i].addr, data, areas[i].size,
                areas[i].type, areas[i].prot, areas[i].skip_eextend, areas[i].desc);

        if (data)
            INLINE_SYSCALL(munmap, 2, data, areas[i].size);

        if (ret < 0) {
            SGX_DBG(DBG_E, "Adding pages (%s) to enclave failed: %d\n", areas[i].desc, -ret);
            goto out;
        }
    }

    ret = init_enclave(&enclave_secs, &enclave_sigstruct, &enclave_token);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Initializing enclave failed: %d\n", -ret);
        goto out;
    }

    create_tcs_mapper((void *) enclave_secs.baseaddr + tcs_area->addr,
                      enclave->thread_num);

    struct enclave_dbginfo * dbg = (void *)
            INLINE_SYSCALL(mmap, 6, DBGINFO_ADDR,
                           sizeof(struct enclave_dbginfo),
                           PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                           -1, 0);
    if (IS_ERR_P(dbg)) {
        SGX_DBG(DBG_E, "Cannot allocate debug information (GDB will not work)\n");
    } else {
        dbg->pid = INLINE_SYSCALL(getpid, 0);
        dbg->base = enclave->baseaddr;
        dbg->size = enclave->size;
        dbg->ssaframesize = enclave->ssaframesize;
        dbg->aep  = async_exit_pointer;
        dbg->thread_tids[0] = dbg->pid;
        for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
            dbg->tcs_addrs[i] = tcs_addrs[i];
    }

    ret = 0;

out:
    if (enclave_image >= 0)
        INLINE_SYSCALL(close, 1, enclave_image);

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
        return -ERRNO(fd);

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    if (IS_ERR(ret))
        return -ERRNO(ret);

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
        return -ERRNO(fd);

    int reuse = 1;
    INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

    ret = INLINE_SYSCALL(bind, 3, fd, &addr, sizeof(addr));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    inet_pton4(MCAST_GROUP, sizeof(MCAST_GROUP) - 1,
               &addr.sin_addr.s_addr);

    struct ip_mreq group;
    group.imr_multiaddr.s_addr = addr.sin_addr.s_addr;
    group.imr_interface.s_addr = INADDR_ANY;

    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group));
    if (IS_ERR(ret))
        return -ERRNO(ret);

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
    PAL_NUM id;
    getrand(&id, sizeof(id));
    snprintf(pal_sec->pipe_prefix, sizeof(pal_sec->pipe_prefix), "/graphene/%016lx/", id);
    pal_sec->instance_id = id;
}

int load_manifest (int fd, struct config_store ** config_ptr)
{
    int ret = 0;

    int nbytes = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_END);
    if (IS_ERR(nbytes)) {
        SGX_DBG(DBG_E, "Cannot detect size of manifest file\n");
        return -ERRNO(nbytes);
    }

    struct config_store * config = malloc(sizeof(struct config_store));
    if (!config) {
        SGX_DBG(DBG_E, "Not enough memory for config_store of manifest\n");
        return -ENOMEM;
    }

    void * config_raw = (void *)
        INLINE_SYSCALL(mmap, 6, NULL, nbytes, PROT_READ, MAP_PRIVATE, fd, 0);
    if (IS_ERR_P(config_raw)) {
        SGX_DBG(DBG_E, "Cannot mmap manifest file\n");
        ret = -ERRNO_P(config_raw);
        goto out;
    }

    config->raw_data = config_raw;
    config->raw_size = nbytes;
    config->malloc   = malloc;
    config->free     = NULL;

    const char * errstring = NULL;
    ret = read_config(config, NULL, &errstring);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot read manifest: %s\n", errstring);
        goto out;
    }

    *config_ptr = config;
    ret = 0;

out:
    if (ret < 0) {
        if (config)
            free(config);
        if (!IS_ERR_P(config_raw))
            INLINE_SYSCALL(munmap, 2, config_raw, nbytes);
    }
    return ret;
}

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
    if (ret < 0) {
        INLINE_SYSCALL(close, 1, fd);
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

    INLINE_SYSCALL(close, 1, fd);
    if (cpu_count == 0)
        return -PAL_ERROR_STREAMNOTEXIST;
    return cpu_count;
}

static int load_enclave (struct pal_enclave * enclave,
                         char * manifest_uri,
                         char * exec_uri,
                         char * args, size_t args_size,
                         char * env, size_t env_size,
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
    int num_cpus = get_cpu_count();
    if (num_cpus < 0) {
        return num_cpus;
    }
    pal_sec->num_cpus = num_cpus;

#ifdef DEBUG
    size_t env_i = 0;
    while (env_i < env_size) {
        if (strcmp_static(&env[env_i], "IN_GDB=1")) {
            SGX_DBG(DBG_I, "[ Running under GDB ]\n");
            pal_sec->in_gdb = true;
        }

        if (strcmp_static(&env[env_i], "LD_PRELOAD=")) {
            uint64_t env_i_size = strnlen(&env[env_i], env_size - env_i) + 1;
            memmove(&env[env_i], &env[env_i + env_i_size], env_size - env_i - env_i_size);
            env_size -= env_i_size;
            continue;
        }

        env_i += strnlen(&env[env_i], env_size - env_i) + 1;
    }
#endif

    char cfgbuf[CONFIG_MAX];

    enclave->manifest = INLINE_SYSCALL(open, 3, manifest_uri + 5,
                                       O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->manifest)) {
         SGX_DBG(DBG_E, "Cannot open manifest %s\n", manifest_uri);
         return -EINVAL;
    }

    ret = load_manifest(enclave->manifest, &enclave->config);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Invalid manifest: %s\n", manifest_uri);
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
                SGX_DBG(DBG_I, "Inferred executable cannot be opened: %s.  This may be ok, "
                       "or may represent a manifest misconfiguration. This typically "
                       "represents advanced usage, and if it is not what you intended, "
                       "try setting the loader.exec field in the manifest.\n", exec_uri);
                enclave->exec = -1;
            } else {
                SGX_DBG(DBG_E, "Cannot open executable %s\n", exec_uri);
                return -EINVAL;
            }
        }
    } else {
        enclave->exec = -1;
    }

    if (get_config(enclave->config, "sgx.sigfile", cfgbuf, CONFIG_MAX) < 0) {
        SGX_DBG(DBG_E, "Sigstruct file not found ('sgx.sigfile' must be specified in manifest)\n");
        return -EINVAL;
    }

    char * sig_uri = resolve_uri(cfgbuf, &errstring);
    if (!sig_uri) {
        SGX_DBG(DBG_E, "%s: %s\n", errstring, cfgbuf);
        return -EINVAL;
    }

    if (!strcmp_static(sig_uri + strlen(sig_uri) - 4, ".sig")) {
        SGX_DBG(DBG_E, "Invalid sigstruct file URI as %s\n", cfgbuf);
        free(sig_uri);
        return -EINVAL;
    }

    enclave->sigfile = INLINE_SYSCALL(open, 3, sig_uri + 5, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->sigfile)) {
        SGX_DBG(DBG_E, "Cannot open sigstruct file %s\n", sig_uri);
        free(sig_uri);
        return -EINVAL;
    }

    char * token_uri = alloc_concat(sig_uri, strlen(sig_uri) - 4, ".token", -1);
    free(sig_uri);

    enclave->token = INLINE_SYSCALL(open, 3, token_uri + 5, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->token)) {
        SGX_DBG(DBG_E, "Cannot open token \'%s\'. Use \'"
                PAL_FILE("pal-sgx-get-token")
                "\' on the runtime host or run \'make SGX_RUN=1\' "
                "in the Graphene source to create the token file.\n",
                token_uri);
        free(token_uri);
        return -EINVAL;
    }
    SGX_DBG(DBG_I, "Token file: %s\n", token_uri);
    free(token_uri);

    ret = initialize_enclave(enclave);
    if (ret < 0)
        return ret;

    if (!pal_sec->instance_id)
        create_instance(&enclave->pal_sec);

    memcpy(pal_sec->manifest_name, manifest_uri, strlen(manifest_uri) + 1);

    if (enclave->exec == -1) {
        memset(pal_sec->exec_name, 0, sizeof(PAL_SEC_STR));
    } else {
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

    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;

    ret = init_aesm_targetinfo(&pal_sec->aesm_targetinfo);
    if (ret < 0)
        return ret;

    current_enclave = enclave;
    map_tcs(INLINE_SYSCALL(gettid, 0), /* created_by_pthread=*/false);

    /* start running trusted PAL */
    ecall_enclave_start(args, args_size, env, env_size);

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM exit_time = 0;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    exit_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    unmap_tcs();
    INLINE_SYSCALL(exit, 0);
    return 0;
}

int main (int argc, char ** argv, char ** envp)
{
    char * manifest_uri = NULL;
    char * exec_uri = NULL;
    const char * pal_loader = argv[0];
    int ret = 0;
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
        ret = is_child;
        goto out;
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
        goto usage;
    }

    char filebuf[4];
    /* Check if the first argument is a executable. If it is, try finding
       all the possible manifest files. */
    INLINE_SYSCALL(read, 3, fd, filebuf, 4);
    INLINE_SYSCALL(close, 1, fd);

    char sgx_manifest[URI_MAX];
    size_t len = sizeof(sgx_manifest);
    ret = get_base_name(exec_uri + static_strlen("file:"), sgx_manifest, &len);
    if (ret < 0) {
        goto out;
    }

    if (strcmp_static(sgx_manifest + len - strlen(".manifest"), ".manifest")) {
        strcpy_static(sgx_manifest + len, ".sgx", sizeof(sgx_manifest) - len);
    } else if (!strcmp_static(sgx_manifest + len - strlen(".manifest.sgx"),
                              ".manifest.sgx")) {
        strcpy_static(sgx_manifest + len, ".manifest.sgx", sizeof(sgx_manifest) - len);
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
        SGX_DBG(DBG_E, "Cannot open manifest file: %s\n", sgx_manifest);
        goto usage;
    }

    SGX_DBG(DBG_I, "Manifest file: %s\n", manifest_uri);
    if (exec_uri)
        SGX_DBG(DBG_I, "Executable file: %s\n", exec_uri);
    else
        SGX_DBG(DBG_I, "Executable file not found\n");

    /*
     * While C does not guarantee that the argv[i] and envp[i] strings are
     * continuous we know that we are running on Linux, which does this. This
     * saves us creating a copy of all argv and envp strings.
     */
    char * args = argv[0];
    size_t args_size = argc > 0 ? (argv[argc - 1] - argv[0]) + strlen(argv[argc - 1]) + 1: 0;

    int envc = 0;
    while (envp[envc] != NULL) {
        envc++;
    }
    char * env = envp[0];
    size_t env_size = envc > 0 ? (envp[envc - 1] - envp[0]) + strlen(envp[envc - 1]) + 1: 0;


    ret = load_enclave(enclave, manifest_uri, exec_uri, args, args_size,
            env, env_size, exec_uri_inferred);

out:
    if (enclave->manifest >= 0)
        INLINE_SYSCALL(close, 1, enclave->manifest);
    if (enclave->exec >= 0)
        INLINE_SYSCALL(close, 1, enclave->exec);
    if (enclave->sigfile >= 0)
        INLINE_SYSCALL(close, 1, enclave->sigfile);
    if (enclave->token >= 0)
        INLINE_SYSCALL(close, 1, enclave->token);
    if (enclave)
        free(enclave);
    if (exec_uri)
        free(exec_uri);
    if (manifest_uri && manifest_uri != sgx_manifest)
        free(manifest_uri);

    return ret;

usage:
    SGX_DBG(DBG_E, "USAGE: %s [executable|manifest] args ...\n", pal_loader);
    ret = -EINVAL;
    goto out;
}
