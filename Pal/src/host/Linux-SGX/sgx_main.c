#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_rtld.h>
#include <hex.h>

#include "debugger/sgx_gdb.h"
#include "rpc_queue.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
#include "sgx_tls.h"

#include <asm/fcntl.h>
#include <asm/socket.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <asm/errno.h>
#include <ctype.h>

#include <sysdep.h>
#include <sysdeps/generic/ldsodefs.h>

size_t g_page_size = PRESET_PAGESIZE;

struct pal_enclave pal_enclave;

static inline
char * alloc_concat(const char * p, size_t plen,
                    const char * s, size_t slen)
{
    plen = (plen != (size_t)-1) ? plen : (p ? strlen(p) : 0);
    slen = (slen != (size_t)-1) ? slen : (s ? strlen(s) : 0);

    char * buf = malloc(plen + slen + 1);
    if (!buf)
        return NULL;

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
    if (!strstartswith_static(uri, URI_PREFIX_FILE)) {
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

    return alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, path_buf, len);
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

    if ((size_t)ret < sizeof(ElfW(Ehdr)))
        return -ENOEXEC;

    const ElfW(Ehdr) * header = (void *) filebuf;
    const ElfW(Phdr) * phdr = (void *) filebuf + header->e_phoff;
    const ElfW(Phdr) * ph;

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
        return -ENOEXEC;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr ; ph < &phdr[header->e_phnum] ; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16)
                return -EINVAL;

            c = &loadcmds[nloadcmds++];
            c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz);
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
            c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
            c->datastart = ph->p_vaddr;
            c->dataend = ph->p_vaddr + ph->p_filesz;
            c->allocend = ph->p_vaddr + ph->p_memsz;
            c->mapoff = ALLOC_ALIGN_DOWN(ph->p_offset);
            c->prot = (ph->p_flags & PF_R ? PROT_READ  : 0)|
                      (ph->p_flags & PF_W ? PROT_WRITE : 0)|
                      (ph->p_flags & PF_X ? PROT_EXEC  : 0)|prot;
        }

    base -= loadcmds[0].mapstart;
    for (c = loadcmds; c < &loadcmds[nloadcmds] ; c++) {
        ElfW(Addr) zero = c->dataend;
        ElfW(Addr) zeroend = ALLOC_ALIGN_UP(c->allocend);
        ElfW(Addr) zeropage = ALLOC_ALIGN_UP(zero);

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
                                       SGX_PAGE_REG, c->prot, /*skip_eextend=*/false,
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
    int                    enclave_image = -1;
    char*                  enclave_uri = NULL;
    sgx_arch_token_t       enclave_token;
    sgx_arch_enclave_css_t enclave_sigstruct;
    sgx_arch_secs_t        enclave_secs;
    unsigned long          enclave_entry_addr;
    unsigned long          heap_min = DEFAULT_HEAP_MIN;

    /* this array may overflow the stack, so we allocate it in BSS */
    static void* tcs_addrs[MAX_DBG_THREADS];

    char cfgbuf[CONFIG_MAX];
    const char* errstring = "out of memory";

    /* Use sgx.enclave_pal_file from manifest if exists */
    if (get_config(enclave->config, "sgx.enclave_pal_file", cfgbuf, sizeof(cfgbuf)) > 0) {
        enclave_uri = resolve_uri(cfgbuf, &errstring);
    } else {
        enclave_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, ENCLAVE_PAL_FILENAME, -1);
    }

    if (!enclave_uri) {
        SGX_DBG(DBG_E,
                "Cannot open in-enclave PAL: %s (incorrect sgx.enclave_pal_file in manifest?)\n",
                errstring);
        ret = -EINVAL;
        goto out;
    }

    enclave_image = INLINE_SYSCALL(open, 3, enclave_uri + URI_PREFIX_FILE_LEN, O_RDONLY, 0);
    if (IS_ERR(enclave_image)) {
        SGX_DBG(DBG_E, "Cannot find enclave image: %s\n", enclave_uri);
        ret = -ERRNO(enclave_image);
        goto out;
    }

    /* Reading sgx.enclave_size from manifest */
    if (get_config(enclave->config, "sgx.enclave_size", cfgbuf, sizeof(cfgbuf)) <= 0) {
        SGX_DBG(DBG_E, "Enclave size is not specified\n");
        ret = -EINVAL;
        goto out;
    }

    enclave->size = parse_int(cfgbuf);
    if (!enclave->size || !IS_POWER_OF_2(enclave->size)) {
        SGX_DBG(DBG_E, "Enclave size not a power of two (an SGX-imposed requirement)\n");
        ret = -EINVAL;
        goto out;
    }

    /* Reading sgx.thread_num from manifest */
    if (get_config(enclave->config, "sgx.thread_num", cfgbuf, sizeof(cfgbuf)) > 0) {
        enclave->thread_num = parse_int(cfgbuf);

        if (enclave->thread_num > MAX_DBG_THREADS) {
            SGX_DBG(DBG_E, "Too many threads to debug\n");
            ret = -EINVAL;
            goto out;
        }
    } else {
        enclave->thread_num = 1;
    }

    if (get_config(enclave->config, "sgx.rpc_thread_num", cfgbuf, sizeof(cfgbuf)) > 0) {
        enclave->rpc_thread_num = parse_int(cfgbuf);

        if (enclave->rpc_thread_num > MAX_RPC_THREADS) {
            SGX_DBG(DBG_E, "Too many RPC threads specified\n");
            ret = -EINVAL;
            goto out;
        }

        if (enclave->rpc_thread_num && enclave->thread_num > RPC_QUEUE_SIZE) {
            SGX_DBG(DBG_E, "Too many threads for exitless feature (more than capacity of RPC queue)\n");
            ret = -EINVAL;
            goto out;
        }
    } else {
        enclave->rpc_thread_num = 0;  /* by default, do not use exitless feature */
    }

    if (get_config(enclave->config, "sgx.static_address", cfgbuf, sizeof(cfgbuf)) > 0 && cfgbuf[0] == '1') {
        enclave->baseaddr = ALIGN_DOWN_POW2(heap_min, enclave->size);
    } else {
        enclave->baseaddr = ENCLAVE_HIGH_ADDRESS;
        heap_min = 0;
    }

    ret = read_enclave_token(enclave->token, &enclave_token);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Reading enclave token failed: %d\n", -ret);
        goto out;
    }
    enclave->pal_sec.enclave_attributes = enclave_token.body.attributes;

    ret = read_enclave_sigstruct(enclave->sigfile, &enclave_sigstruct);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Reading enclave sigstruct failed: %d\n", -ret);
        goto out;
    }

    memset(&enclave_secs, 0, sizeof(enclave_secs));
    enclave_secs.base = enclave->baseaddr;
    enclave_secs.size = enclave->size;
    ret = create_enclave(&enclave_secs, &enclave_token);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Creating enclave failed: %d\n", -ret);
        goto out;
    }

    enclave->ssaframesize = enclave_secs.ssa_frame_size * g_page_size;

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
        int fd;
        bool is_binary; /* only meaningful if fd != -1 */
        unsigned long addr, size, prot;
        enum sgx_page_type type;
    };

    /*
     * 10 for manifest, SSA, TCS, etc
     * + enclave->thread_num for normal stack
     * + enclave->thread_num for signal stack
     */
    int area_num_max = 10 + enclave->thread_num * 2;
    struct mem_area * areas = __alloca(sizeof(areas[0]) * area_num_max);
    int area_num = 0;

    /* The manifest needs to be allocated at the upper end of the enclave
     * memory. That's used by pal_linux_main to find the manifest area. So add
     * it first to the list with memory areas. */
    areas[area_num] = (struct mem_area) {
        .desc = "manifest", .skip_eextend = false, .fd = enclave->manifest,
        .is_binary = false, .addr = 0, .size = ALLOC_ALIGN_UP(manifest_size),
        .prot = PROT_READ, .type = SGX_PAGE_REG
    };
    area_num++;

    areas[area_num] = (struct mem_area) {
        .desc = "ssa", .skip_eextend = false, .fd = -1,
        .is_binary = false, .addr = 0,
        .size = enclave->thread_num * enclave->ssaframesize * SSAFRAMENUM,
        .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
    };
    struct mem_area* ssa_area = &areas[area_num++];

    areas[area_num] = (struct mem_area) {
        .desc = "tcs", .skip_eextend = false, .fd = -1,
        .is_binary = false, .addr = 0, .size = enclave->thread_num * g_page_size,
        .prot = 0, .type = SGX_PAGE_TCS
    };
    struct mem_area* tcs_area = &areas[area_num++];

    areas[area_num] = (struct mem_area) {
        .desc = "tls", .skip_eextend = false, .fd = -1,
        .is_binary = false, .addr = 0, .size = enclave->thread_num * g_page_size,
        .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
    };
    struct mem_area* tls_area = &areas[area_num++];

    struct mem_area* stack_areas = &areas[area_num]; /* memorize for later use */
    for (uint32_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area) {
            .desc = "stack", .skip_eextend = false, .fd = -1,
            .is_binary = false, .addr = 0, .size = ENCLAVE_STACK_SIZE,
            .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
        };
        area_num++;
    }

    struct mem_area* sig_stack_areas = &areas[area_num]; /* memorize for later use */
    for (uint32_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area) {
            .desc = "sig_stack", .skip_eextend = false, .fd = -1,
            .is_binary = false, .addr = 0, .size = ENCLAVE_SIG_STACK_SIZE,
            .prot = PROT_READ | PROT_WRITE, .type = SGX_PAGE_REG
        };
        area_num++;
    }

    areas[area_num] = (struct mem_area) {
        .desc = "pal", .skip_eextend = false, .fd = enclave_image,
        .is_binary = true, .addr = 0, .size = 0 /* set below */,
        .prot = 0, .type = SGX_PAGE_REG
    };
    struct mem_area* pal_area = &areas[area_num++];

    ret = scan_enclave_binary(enclave_image, &pal_area->addr, &pal_area->size, &enclave_entry_addr);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Scanning Pal binary (%s) failed: %d\n", enclave_uri, -ret);
        goto out;
    }

    struct mem_area* exec_area = NULL;
    if (enclave->exec != -1) {
        areas[area_num] = (struct mem_area) {
            .desc = "exec", .skip_eextend = false, .fd = enclave->exec,
            .is_binary = true, .addr = 0, .size = 0 /* set below */,
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
        if (exec_area->addr + exec_area->size > pal_area->addr - MEMORY_GAP) {
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
                    .desc = "free", .skip_eextend = true, .fd = -1,
                    .is_binary = false, .addr = addr, .size = populating - addr,
                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC, .type = SGX_PAGE_REG
                };
                area_num++;
            }

            populating = SATURATED_P_SUB(exec_area->addr, MEMORY_GAP, 0);
        }
    }

    if (populating > heap_min) {
        areas[area_num] = (struct mem_area) {
            .desc = "free", .skip_eextend = true, .fd = -1,
            .is_binary = false, .addr = heap_min, .size = populating - heap_min,
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

        if (!strcmp_static(areas[i].desc, "tls")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
            if (IS_ERR_P(data) || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tls pages failed\n");
                goto out;
            }

            for (uint32_t t = 0 ; t < enclave->thread_num ; t++) {
                struct enclave_tls * gs = data + g_page_size * t;
                memset(gs, 0, g_page_size);
                assert(sizeof(*gs) <= g_page_size);
                gs->common.self = (PAL_TCB *)(
                    tls_area->addr + g_page_size * t + enclave_secs.base);
                gs->enclave_size = enclave->size;
                gs->tcs_offset = tcs_area->addr + g_page_size * t;
                gs->initial_stack_offset =
                    stack_areas[t].addr + ENCLAVE_STACK_SIZE;
                gs->sig_stack_low =
                    sig_stack_areas[t].addr + enclave_secs.base;
                gs->sig_stack_high =
                    sig_stack_areas[t].addr + ENCLAVE_SIG_STACK_SIZE +
                    enclave_secs.base;
                gs->ssa = (void *) ssa_area->addr +
                    enclave->ssaframesize * SSAFRAMENUM * t +
                    enclave_secs.base;
                gs->gpr = gs->ssa +
                    enclave->ssaframesize - sizeof(sgx_pal_gpr_t);
                gs->manifest_size = manifest_size;
                gs->heap_min = (void *) enclave_secs.base + heap_min;
                gs->heap_max = (void *) enclave_secs.base + pal_area->addr - MEMORY_GAP;
                if (exec_area) {
                    gs->exec_addr = (void *) enclave_secs.base + exec_area->addr;
                    gs->exec_size = exec_area->size;
                }
                gs->thread = NULL;
            }
        } else if (!strcmp_static(areas[i].desc, "tcs")) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ|PROT_WRITE,
                                           MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
            if (IS_ERR_P(data) || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tcs pages failed\n");
                goto out;
            }

            for (uint32_t t = 0 ; t < enclave->thread_num ; t++) {
                sgx_arch_tcs_t * tcs = data + g_page_size * t;
                memset(tcs, 0, g_page_size);
                tcs->ossa = ssa_area->addr +
                    enclave->ssaframesize * SSAFRAMENUM * t;
                tcs->nssa = SSAFRAMENUM;
                tcs->oentry = enclave_entry_addr;
                tcs->ofs_base = 0;
                tcs->ogs_base = tls_area->addr + t * g_page_size;
                tcs->ofs_limit = 0xfff;
                tcs->ogs_limit = 0xfff;
                tcs_addrs[t] = (void *) enclave_secs.base + tcs_area->addr + g_page_size * t;
            }
        } else if (areas[i].fd != -1) {
            data = (void *) INLINE_SYSCALL(mmap, 6, NULL, areas[i].size,
                                           PROT_READ,
                                           MAP_FILE|MAP_PRIVATE,
                                           areas[i].fd, 0);
            if (IS_ERR_P(data) || data == NULL) {
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

    create_tcs_mapper((void *) enclave_secs.base + tcs_area->addr, enclave->thread_num);

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
    free(enclave_uri);

    return ret;
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

static int load_manifest (int fd, struct config_store ** config_ptr)
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
static int get_cpu_count(void) {
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
                         int manifest_fd,
                         char * manifest_uri,
                         char * exec_uri,
                         char * args, size_t args_size,
                         char * env, size_t env_size,
                         bool exec_uri_inferred)
{
    struct pal_sec * pal_sec = &enclave->pal_sec;
    int ret;
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
        if (!strcmp_static(&env[env_i], "IN_GDB=1")) {
            SGX_DBG(DBG_I, "[ Running under GDB ]\n");
            pal_sec->in_gdb = true;
        } else if (strstartswith_static(&env[env_i], "LD_PRELOAD=")) {
            uint64_t env_i_size = strnlen(&env[env_i], env_size - env_i) + 1;
            memmove(&env[env_i], &env[env_i + env_i_size], env_size - env_i - env_i_size);
            env_size -= env_i_size;
            continue;
        }

        env_i += strnlen(&env[env_i], env_size - env_i) + 1;
    }
#endif

    enclave->manifest = manifest_fd;

    ret = load_manifest(enclave->manifest, &enclave->config);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Invalid manifest: %s\n", manifest_uri);
        return -EINVAL;
    }

    char cfgbuf[CONFIG_MAX];
    const char * errstring;

    // A manifest can specify an executable with a different base name
    // than the manifest itself.  Always give the exec field of the manifest
    // precedence if specified.
    if (get_config(enclave->config, "loader.exec", cfgbuf, sizeof(cfgbuf)) > 0) {
        exec_uri = resolve_uri(cfgbuf, &errstring);
        exec_uri_inferred = false;
        if (!exec_uri) {
            SGX_DBG(DBG_E, "%s: %s\n", errstring, cfgbuf);
            return -EINVAL;
        }
    }

    enclave->exec = INLINE_SYSCALL(open, 3, exec_uri + URI_PREFIX_FILE_LEN,
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

    if (get_config(enclave->config, "sgx.sigfile", cfgbuf, sizeof(cfgbuf)) < 0) {
        SGX_DBG(DBG_E, "Sigstruct file not found ('sgx.sigfile' must be specified in manifest)\n");
        return -EINVAL;
    }

    char * sig_uri = resolve_uri(cfgbuf, &errstring);
    if (!sig_uri) {
        SGX_DBG(DBG_E, "%s: %s\n", errstring, cfgbuf);
        return -EINVAL;
    }

    if (!strendswith(sig_uri, ".sig")) {
        SGX_DBG(DBG_E, "Invalid sigstruct file URI as %s\n", cfgbuf);
        free(sig_uri);
        return -EINVAL;
    }

    enclave->sigfile = INLINE_SYSCALL(open, 3, sig_uri + URI_PREFIX_FILE_LEN,
                                      O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->sigfile)) {
        SGX_DBG(DBG_E, "Cannot open sigstruct file %s\n", sig_uri);
        free(sig_uri);
        return -EINVAL;
    }

    char * token_uri = alloc_concat(sig_uri, strlen(sig_uri) - static_strlen(".sig"), ".token", -1);
    free(sig_uri);
    if (!token_uri) {
        INLINE_SYSCALL(close, 1, enclave->sigfile);
        return -ENOMEM;
    }

    enclave->token = INLINE_SYSCALL(open, 3, token_uri + URI_PREFIX_FILE_LEN,
                                    O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(enclave->token)) {
        SGX_DBG(DBG_E, "Cannot open token \'%s\'. Use \'"
                PAL_FILE("pal-sgx-get-token")
                "\' on the runtime host or run \'make SGX=1 sgx-tokens\' "
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

    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;

    if (get_config(enclave->config, "sgx.ra_client_spid", cfgbuf, sizeof(cfgbuf)) > 0) {
        /* initialize communication with Quoting Enclave only if app requests Quote retrieval */
        ret = init_quoting_enclave_targetinfo(&pal_sec->qe_targetinfo);
        if (ret < 0)
            return ret;
    }

    void* alt_stack = (void*)INLINE_SYSCALL(mmap, 6, NULL, ALT_STACK_SIZE,
                                            PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_ERR_P(alt_stack))
        return -ENOMEM;

    /* initialize TCB at the top of the alternative stack */
    PAL_TCB_URTS* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_URTS);
    pal_tcb_urts_init(
        tcb, /*stack=*/NULL, alt_stack); /* main thread uses the stack provided by Linux */
    pal_thread_init(tcb);

    /* start running trusted PAL */
    ecall_enclave_start(args, args_size, env, env_size);

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM exit_time = 0;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    exit_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    unmap_tcs();
    INLINE_SYSCALL(munmap, 2, alt_stack, ALT_STACK_SIZE);
    INLINE_SYSCALL(exit, 0);
    return 0;
}

/* Grow stack of main thread to THREAD_STACK_SIZE by allocating a large dummy array and probing
 * each stack page (Linux dynamically grows the stack of the main thread but gets confused with
 * huge-jump stack accesses coming from within the enclave). Note that other, non-main threads
 * are created manually via clone(.., THREAD_STACK_SIZE, ..) and thus do not need this hack. */
static void __attribute__ ((noinline)) force_linux_to_grow_stack() {
    char dummy[THREAD_STACK_SIZE];
    for (uint64_t i = 0; i < sizeof(dummy); i += PRESET_PAGESIZE) {
        /* touch each page on the stack just to make it is not optimized away */
        __asm__ volatile("movq %0, %%rbx\r\n"
                         "movq (%%rbx), %%rbx\r\n"
                         : : "r"(&dummy[i]) : "%rbx");
    }
}

int main (int argc, char ** argv, char ** envp)
{
    char * manifest_uri = NULL;
    char * exec_uri = NULL;
    const char * pal_loader = argv[0];
    int fd = -1;
    int ret = 0;
    bool exec_uri_inferred = false; // Handle the case where the exec uri is
                                    // inferred from the manifest name somewhat
                                    // differently

    force_linux_to_grow_stack();

    argc--;
    argv++;

    int is_child = sgx_init_child_process(&pal_enclave.pal_sec);
    if (is_child < 0) {
        ret = is_child;
        goto out;
    }

    if (!is_child) {
        /* occupy PROC_INIT_FD so no one will use it */
        INLINE_SYSCALL(dup2, 2, 0, PROC_INIT_FD);

        if (!argc)
            goto usage;

        if (!strcmp_static(argv[0], URI_PREFIX_FILE)) {
            exec_uri = alloc_concat(argv[0], -1, NULL, -1);
        } else {
            exec_uri = alloc_concat(URI_PREFIX_FILE, -1, argv[0], -1);
        }
    } else {
        exec_uri = alloc_concat(pal_enclave.pal_sec.exec_name, -1, NULL, -1);
    }

    if (!exec_uri) {
        ret = -ENOMEM;
        goto out;
    }

    fd = INLINE_SYSCALL(open, 3, exec_uri + URI_PREFIX_FILE_LEN, O_RDONLY|O_CLOEXEC, 0);
    if (IS_ERR(fd)) {
        SGX_DBG(DBG_E, "Input file not found: %s\n", exec_uri);
        ret = fd;
        goto usage;
    }

    char file_first_four_bytes[4];
    ret = INLINE_SYSCALL(read, 3, fd, file_first_four_bytes, sizeof(file_first_four_bytes));
    if (IS_ERR(ret)) {
        goto out;
    }
    if (ret != sizeof(file_first_four_bytes)) {
        ret = -EINVAL;
        goto out;
    }

    char manifest_base_name[URI_MAX];
    size_t manifest_base_name_len = sizeof(manifest_base_name);
    ret = get_base_name(exec_uri + URI_PREFIX_FILE_LEN, manifest_base_name,
                        &manifest_base_name_len);
    if (ret < 0) {
        goto out;
    }

    if (strendswith(manifest_base_name, ".manifest")) {
        if (!strcpy_static(manifest_base_name + manifest_base_name_len, ".sgx",
                           sizeof(manifest_base_name) - manifest_base_name_len)) {
            ret = -E2BIG;
            goto out;
        }
    } else if (!strendswith(manifest_base_name, ".manifest.sgx")) {
        if (!strcpy_static(manifest_base_name + manifest_base_name_len, ".manifest.sgx",
                           sizeof(manifest_base_name) - manifest_base_name_len)) {
            ret = -E2BIG;
            goto out;
        }
    }

    int manifest_fd = -1;

    if (memcmp(file_first_four_bytes, "\177ELF", sizeof(file_first_four_bytes))) {
        /* exec_uri doesn't refer to ELF executable, so it must refer to the
         * manifest. Verify this and update exec_uri with the manifest suffix
         * removed.
         */

        size_t exec_uri_len = strlen(exec_uri);
        if (strendswith(exec_uri, ".manifest")) {
            exec_uri[exec_uri_len - static_strlen(".manifest")] = '\0';
        } else if (strendswith(exec_uri, ".manifest.sgx")) {
            INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET);
            manifest_fd = fd;

            exec_uri[exec_uri_len - static_strlen(".manifest.sgx")] = '\0';
        } else {
            SGX_DBG(DBG_E, "Invalid manifest file specified: %s\n", exec_uri);
            goto usage;
        }

        exec_uri_inferred = true;
    }

    if (manifest_fd == -1) {
        INLINE_SYSCALL(close, 1, fd);
        fd = manifest_fd = INLINE_SYSCALL(open, 3, manifest_base_name, O_RDONLY|O_CLOEXEC, 0);
        if (IS_ERR(fd)) {
            SGX_DBG(DBG_E, "Cannot open manifest file: %s\n", manifest_base_name);
            goto usage;
        }
    }

    manifest_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, manifest_base_name, -1);
    if (!manifest_uri) {
        ret = -ENOMEM;
        goto out;
    }

    SGX_DBG(DBG_I, "Manifest file: %s\n", manifest_uri);
    if (exec_uri_inferred)
        SGX_DBG(DBG_I, "Inferred executable file: %s\n", exec_uri);
    else
        SGX_DBG(DBG_I, "Executable file: %s\n", exec_uri);

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

    ret = load_enclave(&pal_enclave, manifest_fd, manifest_uri, exec_uri, args, args_size, env, env_size,
                       exec_uri_inferred);

out:
    if (pal_enclave.exec >= 0)
        INLINE_SYSCALL(close, 1, pal_enclave.exec);
    if (pal_enclave.sigfile >= 0)
        INLINE_SYSCALL(close, 1, pal_enclave.sigfile);
    if (pal_enclave.token >= 0)
        INLINE_SYSCALL(close, 1, pal_enclave.token);
    if (!IS_ERR(fd))
        INLINE_SYSCALL(close, 1, fd);
    free(exec_uri);
    free(manifest_uri);

    return ret;

usage:
    SGX_DBG(DBG_E, "USAGE: %s [executable|manifest] args ...\n", pal_loader);
    ret = -EINVAL;
    goto out;
}
