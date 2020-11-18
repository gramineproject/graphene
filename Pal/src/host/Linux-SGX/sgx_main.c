/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/* FIXME: Sorting+re-grouping includes here causes tons of
 * "../../../include/sysdeps/generic/ldsodefs.h:30:32: error: unknown type name ‘Elf__ELF_NATIVE_CLASS_Addr’
 *   #define ElfW(type)       _ElfW(Elf, __ELF_NATIVE_CLASS, type)"
 * errors.
 */
#include "pal_internal-arch.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_rtld.h"
#include "hex.h"
#include "toml.h"
#include "topo_info.h"

#include "gdb_integration/sgx_gdb.h"
#include "linux_utils.h"
#include "rpc_queue.h"
#include "sgx_api.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
#include "sgx_tls.h"

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/socket.h>
#include <ctype.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/auxv.h>

#include "sysdep.h"
#include "sysdeps/generic/ldsodefs.h"

size_t g_page_size = PRESET_PAGESIZE;

char* g_pal_loader_path = NULL;
char* g_libpal_path = NULL;

struct pal_enclave g_pal_enclave;

static int scan_enclave_binary(int fd, unsigned long* base, unsigned long* size,
                               unsigned long* entry) {
    int ret = 0;

    if (IS_ERR(ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET)))
        return -ERRNO(ret);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if ((size_t)ret < sizeof(ElfW(Ehdr)))
        return -ENOEXEC;

    const ElfW(Ehdr)* header = (void*)filebuf;
    const ElfW(Phdr)* phdr   = (void*)filebuf + header->e_phoff;
    const ElfW(Phdr)* ph;

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0)
        return -ENOEXEC;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr; ph < &phdr[header->e_phnum]; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16)
                return -EINVAL;

            c = &loadcmds[nloadcmds++];
            c->mapstart = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend   = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_memsz);
        }

    *base = loadcmds[0].mapstart;
    *size = loadcmds[nloadcmds - 1].mapend - loadcmds[0].mapstart;
    if (entry)
        *entry = header->e_entry;
    return 0;
}

static int load_enclave_binary(sgx_arch_secs_t* secs, int fd, unsigned long base,
                               unsigned long prot) {
    int ret = 0;

    if (IS_ERR(ret = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_SET)))
        return -ERRNO(ret);

    char filebuf[FILEBUF_SIZE];
    ret = INLINE_SYSCALL(read, 3, fd, filebuf, FILEBUF_SIZE);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    const ElfW(Ehdr)* header = (void*)filebuf;
    const ElfW(Phdr)* phdr   = (void*)filebuf + header->e_phoff;
    const ElfW(Phdr)* ph;

    struct loadcmd {
        ElfW(Addr) mapstart, mapend, datastart, dataend, allocend;
        unsigned int mapoff;
        int prot;
    } loadcmds[16], *c;
    int nloadcmds = 0;

    for (ph = phdr; ph < &phdr[header->e_phnum]; ph++)
        if (ph->p_type == PT_LOAD) {
            if (nloadcmds == 16)
                return -EINVAL;

            c = &loadcmds[nloadcmds++];
            c->mapstart  = ALLOC_ALIGN_DOWN(ph->p_vaddr);
            c->mapend    = ALLOC_ALIGN_UP(ph->p_vaddr + ph->p_filesz);
            c->datastart = ph->p_vaddr;
            c->dataend   = ph->p_vaddr + ph->p_filesz;
            c->allocend  = ph->p_vaddr + ph->p_memsz;
            c->mapoff    = ALLOC_ALIGN_DOWN(ph->p_offset);
            c->prot = (ph->p_flags & PF_R ? PROT_READ : 0) | (ph->p_flags & PF_W ? PROT_WRITE : 0) |
                      (ph->p_flags & PF_X ? PROT_EXEC : 0) | prot;
        }

    base -= loadcmds[0].mapstart;
    for (c = loadcmds; c < &loadcmds[nloadcmds]; c++) {
        ElfW(Addr) zero     = c->dataend;
        ElfW(Addr) zeroend  = ALLOC_ALIGN_UP(c->allocend);
        ElfW(Addr) zeropage = ALLOC_ALIGN_UP(zero);

        if (zeroend < zeropage)
            zeropage = zeroend;

        if (c->mapend > c->mapstart) {
            void* addr = (void*)INLINE_SYSCALL(mmap, 6, NULL, c->mapend - c->mapstart,
                                               PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, fd,
                                               c->mapoff);

            if (IS_ERR_P(addr))
                return -ERRNO_P(addr);

            if (c->datastart > c->mapstart)
                memset(addr, 0, c->datastart - c->mapstart);

            if (zeropage > zero)
                memset(addr + zero - c->mapstart, 0, zeropage - zero);

            ret = add_pages_to_enclave(secs, (void*)base + c->mapstart, addr,
                                       c->mapend - c->mapstart,
                                       SGX_PAGE_REG, c->prot, /*skip_eextend=*/false,
                                       (c->prot & PROT_EXEC) ? "code" : "data");

            INLINE_SYSCALL(munmap, 2, addr, c->mapend - c->mapstart);

            if (ret < 0)
                return ret;
        }

        if (zeroend > zeropage) {
            ret = add_pages_to_enclave(secs, (void*)base + zeropage, NULL, zeroend - zeropage,
                                       SGX_PAGE_REG, c->prot, false, "bss");
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

static int initialize_enclave(struct pal_enclave* enclave) {
    int ret = 0;
    int enclave_image = -1;
    sgx_arch_token_t enclave_token;
    sgx_arch_enclave_css_t enclave_sigstruct;
    sgx_arch_secs_t enclave_secs;
    unsigned long enclave_entry_addr;
    unsigned long enclave_heap_min;

    int enclave_mem = -1;

    /* this array may overflow the stack, so we allocate it in BSS */
    static void* tcs_addrs[MAX_DBG_THREADS];

    enclave_image = INLINE_SYSCALL(open, 3, enclave->libpal_uri + URI_PREFIX_FILE_LEN, O_RDONLY, 0);
    if (IS_ERR(enclave_image)) {
        SGX_DBG(DBG_E, "Cannot find enclave image: %s\n", enclave->libpal_uri);
        ret = -ERRNO(enclave_image);
        goto out;
    }

    assert(enclave->manifest_root);

    ret = toml_sizestring_in(enclave->manifest_root, "sgx.enclave_size", /*defaultval=*/0,
                             &enclave->size);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.enclave_size\' "
                       "(the value must be put in double quotes!)\n");
        ret = -EINVAL;
        goto out;
    }

    if (!enclave->size || !IS_POWER_OF_2(enclave->size)) {
        SGX_DBG(DBG_E, "Enclave size not a power of two (an SGX-imposed requirement)\n");
        ret = -EINVAL;
        goto out;
    }

    int64_t thread_num_int64;
    ret = toml_int_in(enclave->manifest_root, "sgx.thread_num", /*defaultval=*/0,
                      &thread_num_int64);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.thread_num\'\n");
        ret = -EINVAL;
        goto out;
    }

    if (thread_num_int64 < 0) {
        SGX_DBG(DBG_E, "Negative \'sgx.thread_num\' is impossible\n");
        ret = -EINVAL;
        goto out;
    }

    enclave->thread_num = thread_num_int64;

    if (!enclave->thread_num) {
        SGX_DBG(DBG_I, "Number of enclave threads (\'sgx.thread_num\') is not specified; "
                       "assumed to be 1\n");
        enclave->thread_num = 1;
    }

    if (enclave->thread_num > MAX_DBG_THREADS) {
        SGX_DBG(DBG_E, "Too large \'sgx.thread_num\', maximum allowed is %d\n", MAX_DBG_THREADS);
        ret = -EINVAL;
        goto out;
    }

    int64_t rpc_thread_num_int64;
    ret = toml_int_in(enclave->manifest_root, "sgx.rpc_thread_num", /*defaultval=*/0,
                      &rpc_thread_num_int64);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.rpc_thread_num\'\n");
        ret = -EINVAL;
        goto out;
    }

    if (rpc_thread_num_int64 < 0) {
        SGX_DBG(DBG_E, "Negative \'sgx.rpc_thread_num\' is impossible\n");
        ret = -EINVAL;
        goto out;
    }

    enclave->rpc_thread_num = rpc_thread_num_int64;

    if (enclave->rpc_thread_num > MAX_RPC_THREADS) {
        SGX_DBG(DBG_E, "Too large \'sgx.rpc_thread_num\', maximum allowed is %d\n",
                MAX_RPC_THREADS);
        ret = -EINVAL;
        goto out;
    }

    if (enclave->rpc_thread_num && enclave->thread_num > RPC_QUEUE_SIZE) {
        SGX_DBG(DBG_E,
                "Too many threads for exitless feature (more than capacity of RPC queue)\n");
        ret = -EINVAL;
        goto out;
    }

    int64_t static_address;
    ret = toml_int_in(enclave->manifest_root, "sgx.static_address", /*defaultval=*/0,
                      &static_address);
    if (ret < 0 || (static_address != 0 && static_address != 1)) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.static_address\' (the value must be 0 or 1)\n");
        ret = -EINVAL;
        goto out;
    }

    if (static_address) {
        /* executable is static, i.e. it is non-PIE: enclave base address must cover code segment
         * loaded at 0x400000, and heap cannot start at zero (modern OSes do not allow this) */
        enclave->baseaddr = DEFAULT_ENCLAVE_BASE;
        enclave_heap_min  = DEFAULT_HEAP_MIN;
    } else {
        /* executable is not static, i.e. it is PIE: enclave base address can be arbitrary (we
         * choose it same as enclave_size), and heap can start immediately at this base address */
        enclave->baseaddr = enclave->size;
        enclave_heap_min  = 0;
    }

    int64_t enable_stats_int64;
    ret = toml_int_in(enclave->manifest_root, "sgx.enable_stats", /*defaultval=*/0,
                      &enable_stats_int64);
    if (ret < 0 || (enable_stats_int64 != 0 && enable_stats_int64 != 1)) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.enable_stats\' (the value must be 0 or 1)\n");
        ret = -EINVAL;
        goto out;
    }
    g_sgx_enable_stats = !!enable_stats_int64;

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
        const char* desc;
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
    struct mem_area* areas = __alloca(sizeof(areas[0]) * area_num_max);
    int area_num = 0;

    /* The manifest needs to be allocated at the upper end of the enclave
     * memory. That's used by pal_linux_main to find the manifest area. So add
     * it first to the list with memory areas. */
    areas[area_num] = (struct mem_area){.desc         = "manifest",
                                        .skip_eextend = false,
                                        .fd           = enclave->manifest,
                                        .is_binary    = false,
                                        .addr         = 0,
                                        .size         = ALLOC_ALIGN_UP(manifest_size),
                                        .prot         = PROT_READ,
                                        .type         = SGX_PAGE_REG};
    area_num++;

    areas[area_num] =
        (struct mem_area){.desc         = "ssa",
                          .skip_eextend = false,
                          .fd           = -1,
                          .is_binary    = false,
                          .addr         = 0,
                          .size         = enclave->thread_num * enclave->ssaframesize * SSAFRAMENUM,
                          .prot         = PROT_READ | PROT_WRITE,
                          .type         = SGX_PAGE_REG};
    struct mem_area* ssa_area = &areas[area_num++];

    areas[area_num] = (struct mem_area){.desc = "tcs",
                                        .skip_eextend = false,
                                        .fd           = -1,
                                        .is_binary    = false,
                                        .addr         = 0,
                                        .size         = enclave->thread_num * g_page_size,
                                        .prot         = PROT_READ | PROT_WRITE,
                                        .type         = SGX_PAGE_TCS};
    struct mem_area* tcs_area = &areas[area_num++];

    areas[area_num] = (struct mem_area){.desc         = "tls",
                                        .skip_eextend = false,
                                        .fd           = -1,
                                        .is_binary    = false,
                                        .addr         = 0,
                                        .size         = enclave->thread_num * g_page_size,
                                        .prot         = PROT_READ | PROT_WRITE,
                                        .type         = SGX_PAGE_REG};
    struct mem_area* tls_area = &areas[area_num++];

    struct mem_area* stack_areas = &areas[area_num]; /* memorize for later use */
    for (uint32_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area){.desc         = "stack",
                                            .skip_eextend = false,
                                            .fd           = -1,
                                            .is_binary    = false,
                                            .addr         = 0,
                                            .size         = ENCLAVE_STACK_SIZE,
                                            .prot         = PROT_READ | PROT_WRITE,
                                            .type         = SGX_PAGE_REG};
        area_num++;
    }

    struct mem_area* sig_stack_areas = &areas[area_num]; /* memorize for later use */
    for (uint32_t t = 0; t < enclave->thread_num; t++) {
        areas[area_num] = (struct mem_area){.desc         = "sig_stack",
                                            .skip_eextend = false,
                                            .fd           = -1,
                                            .is_binary    = false,
                                            .addr         = 0,
                                            .size         = ENCLAVE_SIG_STACK_SIZE,
                                            .prot         = PROT_READ | PROT_WRITE,
                                            .type         = SGX_PAGE_REG};
        area_num++;
    }

    areas[area_num] = (struct mem_area){.desc         = "pal",
                                        .skip_eextend = false,
                                        .fd           = enclave_image,
                                        .is_binary    = true,
                                        .addr         = 0,
                                        .size         = 0 /* set below */,
                                        .prot         = 0,
                                        .type         = SGX_PAGE_REG};
    struct mem_area* pal_area = &areas[area_num++];

    ret = scan_enclave_binary(enclave_image, &pal_area->addr, &pal_area->size, &enclave_entry_addr);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Scanning Pal binary (%s) failed: %d\n", enclave->libpal_uri, -ret);
        goto out;
    }

    struct mem_area* exec_area = NULL;
    areas[area_num] = (struct mem_area){.desc         = "exec",
                                        .skip_eextend = false,
                                        .fd           = enclave->exec,
                                        .is_binary    = true,
                                        .addr         = 0,
                                        .size         = 0 /* set below */,
                                        .prot         = PROT_WRITE,
                                        .type         = SGX_PAGE_REG};
    exec_area = &areas[area_num++];

    ret = scan_enclave_binary(enclave->exec, &exec_area->addr, &exec_area->size, NULL);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Scanning application binary failed: %d\n", -ret);
        goto out;
    }

    unsigned long populating = enclave->size;
    for (int i = 0; i < area_num; i++) {
        if (areas[i].addr)
            continue;
        areas[i].addr = populating - areas[i].size;
        populating = areas[i].addr;
    }

    enclave_entry_addr += pal_area->addr;

    if (exec_area) {
        if (exec_area->addr + exec_area->size > pal_area->addr) {
            SGX_DBG(DBG_E, "Application binary overlaps with Pal binary\n");
            ret = -EINVAL;
            goto out;
        }

        if (exec_area->addr + exec_area->size < populating) {
            if (populating > enclave_heap_min) {
                unsigned long addr = exec_area->addr + exec_area->size;
                if (addr < enclave_heap_min)
                    addr = enclave_heap_min;

                areas[area_num] = (struct mem_area){.desc         = "free",
                                                    .skip_eextend = true,
                                                    .fd           = -1,
                                                    .is_binary    = false,
                                                    .addr         = addr,
                                                    .size         = populating - addr,
                                                    .prot = PROT_READ | PROT_WRITE | PROT_EXEC,
                                                    .type = SGX_PAGE_REG};
                area_num++;
            }

            populating = exec_area->addr;
        }
    }

    if (populating > enclave_heap_min) {
        areas[area_num] = (struct mem_area){.desc         = "free",
                                            .skip_eextend = true,
                                            .fd           = -1,
                                            .is_binary    = false,
                                            .addr         = enclave_heap_min,
                                            .size         = populating - enclave_heap_min,
                                            .prot         = PROT_READ | PROT_WRITE | PROT_EXEC,
                                            .type         = SGX_PAGE_REG};
        area_num++;
    }

    for (int i = 0; i < area_num; i++) {
        if (areas[i].fd != -1 && areas[i].is_binary) {
            ret = load_enclave_binary(&enclave_secs, areas[i].fd, areas[i].addr, areas[i].prot);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Loading enclave binary failed: %d\n", -ret);
                goto out;
            }
            continue;
        }

        void* data = NULL;

        if (!strcmp(areas[i].desc, "tls")) {
            data = (void*)INLINE_SYSCALL(mmap, 6, NULL, areas[i].size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (IS_ERR_P(data) || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tls pages failed\n");
                goto out;
            }

            for (uint32_t t = 0; t < enclave->thread_num; t++) {
                struct enclave_tls* gs = data + g_page_size * t;
                memset(gs, 0, g_page_size);
                assert(sizeof(*gs) <= g_page_size);
                gs->common.self = (PAL_TCB*)(tls_area->addr + g_page_size * t + enclave_secs.base);
                gs->enclave_size = enclave->size;
                gs->tcs_offset = tcs_area->addr + g_page_size * t;
                gs->initial_stack_offset = stack_areas[t].addr + ENCLAVE_STACK_SIZE;
                gs->sig_stack_low = sig_stack_areas[t].addr + enclave_secs.base;
                gs->sig_stack_high =
                    sig_stack_areas[t].addr + ENCLAVE_SIG_STACK_SIZE + enclave_secs.base;
                gs->ssa = (void*)ssa_area->addr + enclave->ssaframesize * SSAFRAMENUM * t +
                          enclave_secs.base;
                gs->gpr = gs->ssa + enclave->ssaframesize - sizeof(sgx_pal_gpr_t);
                gs->manifest_size = manifest_size;
                gs->heap_min = (void*)enclave_secs.base + enclave_heap_min;
                gs->heap_max = (void*)enclave_secs.base + pal_area->addr;
                if (exec_area) {
                    gs->exec_addr = (void*)enclave_secs.base + exec_area->addr;
                    gs->exec_size = exec_area->size;
                }
                gs->thread = NULL;
            }
        } else if (!strcmp(areas[i].desc, "tcs")) {
            data = (void*)INLINE_SYSCALL(mmap, 6, NULL, areas[i].size, PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (IS_ERR_P(data) || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for tcs pages failed\n");
                goto out;
            }

            for (uint32_t t = 0; t < enclave->thread_num; t++) {
                sgx_arch_tcs_t* tcs = data + g_page_size * t;
                memset(tcs, 0, g_page_size);
                tcs->ossa      = ssa_area->addr + enclave->ssaframesize * SSAFRAMENUM * t;
                tcs->nssa      = SSAFRAMENUM;
                tcs->oentry    = enclave_entry_addr;
                tcs->ofs_base  = 0;
                tcs->ogs_base  = tls_area->addr + t * g_page_size;
                tcs->ofs_limit = 0xfff;
                tcs->ogs_limit = 0xfff;
                tcs_addrs[t] = (void*)enclave_secs.base + tcs_area->addr + g_page_size * t;
            }
        } else if (areas[i].fd != -1) {
            data = (void*)INLINE_SYSCALL(mmap, 6, NULL, areas[i].size, PROT_READ,
                                         MAP_FILE | MAP_PRIVATE, areas[i].fd, 0);
            if (IS_ERR_P(data) || data == NULL) {
                /* Note that Graphene currently doesn't handle 0x0 addresses */
                SGX_DBG(DBG_E, "Allocating memory for file %s failed\n", areas[i].desc);
                goto out;
            }
        }

        ret = add_pages_to_enclave(&enclave_secs, (void*)areas[i].addr, data, areas[i].size,
                                   areas[i].type, areas[i].prot, areas[i].skip_eextend,
                                   areas[i].desc);

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

    create_tcs_mapper((void*)enclave_secs.base + tcs_area->addr, enclave->thread_num);

    struct enclave_dbginfo* dbg = (void*)INLINE_SYSCALL(
        mmap, 6, DBGINFO_ADDR, sizeof(struct enclave_dbginfo), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (IS_ERR_P(dbg)) {
        SGX_DBG(DBG_E, "Cannot allocate debug information (GDB will not work)\n");
    } else {
        dbg->pid            = INLINE_SYSCALL(getpid, 0);
        dbg->base           = enclave->baseaddr;
        dbg->size           = enclave->size;
        dbg->ssaframesize   = enclave->ssaframesize;
        dbg->aep            = async_exit_pointer;
        dbg->eresume        = eresume_pointer;
        dbg->thread_tids[0] = dbg->pid;
        for (int i = 0; i < MAX_DBG_THREADS; i++)
            dbg->tcs_addrs[i] = tcs_addrs[i];
    }

    if (g_sgx_enable_stats) {
        /* set TCS.FLAGS.DBGOPTIN in all enclave threads to enable perf counters, Intel PT, etc */
        enclave_mem = INLINE_SYSCALL(open, 3, "/proc/self/mem", O_RDWR | O_LARGEFILE, 0);
        if (IS_ERR(enclave_mem)) {
            SGX_DBG(DBG_E, "Setting TCS.FLAGS.DBGOPTIN failed: %d\n", -enclave_mem);
            goto out;
        }

        for (size_t i = 0; i < enclave->thread_num; i++) {
            uint64_t tcs_flags;
            uint64_t* tcs_flags_ptr = tcs_addrs[i] + offsetof(sgx_arch_tcs_t, flags);

            ret = INLINE_SYSCALL(pread, 4, enclave_mem, &tcs_flags, sizeof(tcs_flags),
                                 (off_t)tcs_flags_ptr);
            if (IS_ERR(ret)) {
                SGX_DBG(DBG_E, "Reading TCS.FLAGS.DBGOPTIN failed: %d\n", -ret);
                goto out;
            }

            tcs_flags |= TCS_FLAGS_DBGOPTIN;

            ret = INLINE_SYSCALL(pwrite, 4, enclave_mem, &tcs_flags, sizeof(tcs_flags),
                                 (off_t)tcs_flags_ptr);
            if (IS_ERR(ret)) {
                SGX_DBG(DBG_E, "Writing TCS.FLAGS.DBGOPTIN failed: %d\n", -ret);
                goto out;
            }
        }
    }

    ret = 0;

out:
    if (enclave_image >= 0)
        INLINE_SYSCALL(close, 1, enclave_image);
    if (enclave_mem >= 0)
        INLINE_SYSCALL(close, 1, enclave_mem);

    return ret;
}

static void create_instance(struct pal_sec* pal_sec) {
    PAL_NUM id = ((uint64_t)rdrand() << 32) | rdrand();
    snprintf(pal_sec->pipe_prefix, sizeof(pal_sec->pipe_prefix), "/graphene/%016lx/", id);
    pal_sec->instance_id = id;
}

static int load_manifest(int fd, toml_table_t** manifest_root_ptr) {
    int ret = 0;
    toml_table_t* manifest_root = NULL;

    int nbytes = INLINE_SYSCALL(lseek, 3, fd, 0, SEEK_END);
    if (IS_ERR(nbytes)) {
        SGX_DBG(DBG_E, "Cannot detect size of manifest file\n");
        return -ERRNO(nbytes);
    }

    void* manifest_addr = (void*)INLINE_SYSCALL(mmap, 6, NULL, nbytes, PROT_READ, MAP_PRIVATE, fd,
                                                0);
    if (IS_ERR_P(manifest_addr)) {
        SGX_DBG(DBG_E, "Cannot mmap manifest file\n");
        ret = -ERRNO_P(manifest_addr);
        goto out;
    }

    char errbuf[256];
    manifest_root = toml_parse(manifest_addr, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        SGX_DBG(DBG_E, "PAL failed at parsing the manifest: %s\n"
                "  Graphene switched to the TOML format recently, please update the manifest\n"
                "  (in particular, string values must be put in double quotes)\n", errbuf);
        ret = -EINVAL;
        goto out;
    }

    *manifest_root_ptr = manifest_root;
    ret = 0;

out:
    if (ret < 0) {
        toml_free(manifest_root);
        if (!IS_ERR_P(manifest_addr))
            INLINE_SYSCALL(munmap, 2, manifest_addr, nbytes);
    }
    return ret;
}

/* Warning: This function does not free up resources on failure - it assumes that the whole process
 * exits after this function's failure. */
static int load_enclave(struct pal_enclave* enclave, int manifest_fd, char* manifest_path,
                        char* exec_path, char* args, size_t args_size, char* env, size_t env_size,
                        bool need_gsgx) {
    struct pal_sec* pal_sec = &enclave->pal_sec;
    int ret;
    size_t exec_path_len = strlen(exec_path);

#if PRINT_ENCLAVE_STAT == 1
    struct timeval tv;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    pal_sec->start_time = tv.tv_sec * 1000000UL + tv.tv_usec;
#endif

    ret = open_sgx_driver(need_gsgx);
    if (ret < 0)
        return ret;

    if (!is_wrfsbase_supported())
        return -EPERM;

    pal_sec->pid = INLINE_SYSCALL(getpid, 0);
    pal_sec->uid = INLINE_SYSCALL(getuid, 0);
    pal_sec->gid = INLINE_SYSCALL(getgid, 0);

    /* we cannot use CPUID(0xb) because it counts even disabled-by-BIOS cores (e.g. HT cores);
     * instead extract info on total number of logical cores, number of physical cores,
     * SMT support etc. by parsing sysfs pseudo-files */
    int online_logical_cores = get_hw_resource("/sys/devices/system/cpu/online", /*count=*/true);
    if (online_logical_cores < 0)
        return online_logical_cores;
    pal_sec->online_logical_cores = online_logical_cores;

    int possible_logical_cores = get_hw_resource("/sys/devices/system/cpu/possible",
                                                 /*count=*/true);
    if (possible_logical_cores < 0)
        return possible_logical_cores;
    pal_sec->possible_logical_cores = possible_logical_cores;

    /* TODO: correctly support offline cores */
    if (possible_logical_cores > 0 && possible_logical_cores > online_logical_cores) {
         printf("Warning: some CPUs seem to be offline; Graphene doesn't take this into account "
                "which may lead to subpar performance\n");
    }

    int core_siblings = get_hw_resource("/sys/devices/system/cpu/cpu0/topology/core_siblings_list",
                                        /*count=*/true);
    if (core_siblings < 0)
        return core_siblings;

    int smt_siblings = get_hw_resource("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
                                       /*count=*/true);
    if (smt_siblings < 0)
        return smt_siblings;
    pal_sec->physical_cores_per_socket = core_siblings / smt_siblings;

    /* array of "logical core -> socket" mappings */
    int* cpu_socket = (int*)malloc(online_logical_cores * sizeof(int));
    if (!cpu_socket)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < online_logical_cores; idx++) {
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", idx);
        cpu_socket[idx] = get_hw_resource(filename, /*count=*/false);
        if (cpu_socket[idx] < 0) {
            SGX_DBG(DBG_E, "Cannot read %s\n", filename);
            ret = cpu_socket[idx];
            free(cpu_socket);
            return ret;
        }
    }
    pal_sec->cpu_socket = cpu_socket;

    ret = get_core_topo_info(&pal_sec->topo_info);
    if (ret < 0)
        return ret;

    /* Get NUMA topology information */
    ret = get_numa_topo_info(&pal_sec->topo_info);
    if (ret < 0)
        return ret;

#ifdef DEBUG
    size_t env_i = 0;
    while (env_i < env_size) {
        if (!strcmp(&env[env_i], "IN_GDB=1")) {
            SGX_DBG(DBG_I, "[ Running under GDB ]\n");
            pal_sec->in_gdb = true;
        } else if (strstartswith(&env[env_i], "LD_PRELOAD=")) {
            uint64_t env_i_size = strnlen(&env[env_i], env_size - env_i) + 1;
            memmove(&env[env_i], &env[env_i + env_i_size], env_size - env_i - env_i_size);
            env_size -= env_i_size;
            continue;
        }

        env_i += strnlen(&env[env_i], env_size - env_i) + 1;
    }

    enclave->debug_map = NULL;
#endif

    enclave->manifest = manifest_fd;

    ret = load_manifest(enclave->manifest, &enclave->manifest_root);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Invalid manifest: %s\n", manifest_path);
        return -EINVAL;
    }

    enclave->libpal_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, g_libpal_path, -1);
    if (!enclave->libpal_uri) {
        SGX_DBG(DBG_E, "Out of memory for enclave->libpal_uri\n");
        return -ENOMEM;
    }

    if (enclave->libpal_uri[URI_PREFIX_FILE_LEN] != '/') {
        SGX_DBG(DBG_E, "Path to in-enclave PAL (%s) must be absolute\n", enclave->libpal_uri);
        return -EINVAL;
    }

    enclave->exec = INLINE_SYSCALL(open, 3, exec_path, O_RDONLY | O_CLOEXEC, 0);
    if (IS_ERR(enclave->exec)) {
        SGX_DBG(DBG_E, "Cannot open executable %s\n", exec_path);
        return -EINVAL;
    }

    char* dummy_sigfile_str = NULL;
    ret = toml_string_in(enclave->manifest_root, "sgx.sigfile", &dummy_sigfile_str);
    if (ret < 0 || dummy_sigfile_str) {
        SGX_DBG(DBG_E, "sgx.sigfile is not supported anymore. Please update your manifest "
                       "according to the current documentation.\n");
        return -EINVAL;
    }

    char* sig_path = alloc_concat(exec_path, exec_path_len, ".sig", -1);
    if (!sig_path) {
        return -ENOMEM;
    }

    enclave->sigfile = INLINE_SYSCALL(open, 3, sig_path, O_RDONLY | O_CLOEXEC, 0);
    if (IS_ERR(enclave->sigfile)) {
        SGX_DBG(DBG_E, "Cannot open sigstruct file %s\n", sig_path);
        return -EINVAL;
    }
    free(sig_path);

    char* token_path = alloc_concat(exec_path, exec_path_len, ".token", -1);
    if (!token_path) {
        return -ENOMEM;
    }

    enclave->token = INLINE_SYSCALL(open, 3, token_path, O_RDONLY | O_CLOEXEC, 0);
    if (IS_ERR(enclave->token)) {
        SGX_DBG(DBG_E,
                "Cannot open token %s. Use pal-sgx-get-token on the runtime host or run "
                "`make SGX=1 sgx-tokens` in the Graphene source to create the token file.\n",
                token_path);
        return -EINVAL;
    }
    SGX_DBG(DBG_I, "Token file: %s\n", token_path);
    free(token_path);

    ret = initialize_enclave(enclave);
    if (ret < 0)
        return ret;

    if (!pal_sec->instance_id)
        create_instance(&enclave->pal_sec);

    size_t manifest_path_size = strlen(manifest_path) + 1;
    if (URI_PREFIX_FILE_LEN + manifest_path_size > ARRAY_SIZE(pal_sec->manifest_name)) {
        return -E2BIG;
    }
    memcpy(pal_sec->manifest_name, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN);
    memcpy(pal_sec->manifest_name + URI_PREFIX_FILE_LEN, manifest_path, manifest_path_size);

    if (sizeof(pal_sec->exec_name) < URI_PREFIX_FILE_LEN + exec_path_len + 1) {
        return -E2BIG;
    }
    memcpy(pal_sec->exec_name, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN);
    memcpy(pal_sec->exec_name + URI_PREFIX_FILE_LEN, exec_path, exec_path_len + 1);

    ret = sgx_signal_setup();
    if (ret < 0)
        return ret;


    int64_t sgx_remote_attestation_int;
    ret = toml_int_in(enclave->manifest_root, "sgx.remote_attestation", /*defaultval=*/0,
                      &sgx_remote_attestation_int);
    if (ret < 0 || (sgx_remote_attestation_int != 0 && sgx_remote_attestation_int != 1)) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.remote_attestation\' (the value must be 0 or 1)\n");
        return -EINVAL;
    }

    char* sgx_ra_client_spid_str = NULL;
    ret = toml_string_in(enclave->manifest_root, "sgx.ra_client_spid", &sgx_ra_client_spid_str);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.ra_client_spid\' "
                       "(the value must be put in double quotes!)\n");
        return -EINVAL;
    }

    int64_t sgx_ra_client_linkable_int;
    ret = toml_int_in(enclave->manifest_root, "sgx.ra_client_linkable", /*defaultval=*/-1,
                      &sgx_ra_client_linkable_int);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.ra_client_linkable\'\n");
        return -EINVAL;
    }

    if (sgx_remote_attestation_int != 1 &&
            (sgx_ra_client_spid_str || sgx_ra_client_linkable_int >= 0)) {
        SGX_DBG(DBG_E,
                "Detected EPID remote attestation parameters \'ra_client_spid\' and/or "
                "\'ra_client_linkable\' in the manifest but no \'remote_attestation\' parameter. "
                "Please add \'sgx.remote_attestation = 1\' to the manifest.\n");
        return -EINVAL;
    }

    /* EPID is used if SPID is a non-empty string in manifest, otherwise DCAP/ECDSA */
    bool is_epid = false;
    if (sgx_ra_client_spid_str && strlen(sgx_ra_client_spid_str))
        is_epid = true;
    free(sgx_ra_client_spid_str);

    if (sgx_remote_attestation_int == 1) {
        /* initialize communication with Quoting Enclave only if app requests attestation */
        SGX_DBG(DBG_I, "Using SGX %s attestation\n", is_epid ? "EPID" : "DCAP/ECDSA");
        ret = init_quoting_enclave_targetinfo(is_epid, &pal_sec->qe_targetinfo);
        if (ret < 0)
            return ret;
    }

    void* alt_stack = (void*)INLINE_SYSCALL(mmap, 6, NULL, ALT_STACK_SIZE, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_ERR_P(alt_stack))
        return -ENOMEM;

    /* initialize TCB at the top of the alternative stack */
    PAL_TCB_URTS* tcb = alt_stack + ALT_STACK_SIZE - sizeof(PAL_TCB_URTS);
    pal_tcb_urts_init(tcb, /*stack=*/NULL,
                      alt_stack); /* main thread uses the stack provided by Linux */
    ret = pal_thread_init(tcb);
    if (ret < 0)
        return ret;

    /* start running trusted PAL */
    ecall_enclave_start(enclave->libpal_uri, args, args_size, env, env_size);

    unmap_tcs();
    INLINE_SYSCALL(munmap, 2, alt_stack, ALT_STACK_SIZE);
    INLINE_SYSCALL(exit, 0);
    return 0;
}

/* Grow the stack of the main thread to THREAD_STACK_SIZE by probing each stack page above current
 * stack pointer (Linux dynamically grows the stack of the main thread but gets confused with
 * huge-jump stack accesses coming from within the enclave). Note that other, non-main threads
 * are created manually via clone(.., THREAD_STACK_SIZE, ..) and thus do not need this hack. */
static void force_linux_to_grow_stack(void) {
    ARCH_PROBE_STACK(THREAD_STACK_SIZE, PRESET_PAGESIZE);
}

int main(int argc, char* argv[], char* envp[]) {
    char* manifest_path = NULL;
    char* exec_path = NULL;
    int exec_fd = -1;
    int manifest_fd = -1;
    int ret = 0;
    bool need_gsgx = true;

    force_linux_to_grow_stack();

    if (argc < 4)
        goto usage;

    g_pal_loader_path = get_main_exec_path();
    if (!g_pal_loader_path) {
        ret = -ENOMEM;
        goto out;
    }

    /* check whether host kernel supports FSGSBASE feature, otherwise we need the GSGX driver */
    if (getauxval(AT_HWCAP2) & 0x2) {
        need_gsgx = false;
    }

    g_libpal_path = strdup(argv[1]);
    if (!g_libpal_path) {
        ret = -ENOMEM;
        goto out;
    }

    // Are we the first in this Graphene's namespace?
    bool first_process = !strcmp(argv[2], "init");
    if (!first_process && strcmp(argv[2], "child")) {
        goto usage;
    }

    if (first_process) {
        /* The initial Graphene process is special - it was started by the user, so `exec_path` may
         * either contain a path to the executable or to a manifest. */

        exec_path = strdup(argv[3]);
        if (!exec_path) {
            ret = -ENOMEM;
            goto out;
        }

        if (strendswith(exec_path, ".manifest.sgx")) {
            manifest_path = strdup(exec_path);
        } else if (strendswith(exec_path, ".manifest")) {
            manifest_path = alloc_concat(exec_path, -1, ".sgx", -1);
        } else {
            manifest_path = alloc_concat(exec_path, -1, ".manifest.sgx", -1);
        }
        if (!manifest_path) {
            ret = -ENOMEM;
            goto out;
        }

        exec_fd = INLINE_SYSCALL(open, 3, exec_path, O_RDONLY | O_CLOEXEC, 0);
        if (IS_ERR(exec_fd)) {
            SGX_DBG(DBG_E, "Input file not found: %s\n", exec_path);
            goto usage;
        }

        char file_first_four_bytes[4];
        ret = INLINE_SYSCALL(read, 3, exec_fd, file_first_four_bytes, sizeof(file_first_four_bytes));
        if (IS_ERR(ret)) {
            goto out;
        }
        if (ret != sizeof(file_first_four_bytes)) {
            ret = -EINVAL;
            goto out;
        }

        if (memcmp(file_first_four_bytes, "\177ELF", sizeof(file_first_four_bytes))) {
            /* exec_path doesn't refer to ELF executable, so it must refer to the
             * manifest. Verify this and update exec_path with the manifest suffix
             * removed.
             */

            if (strendswith(exec_path, ".manifest")) {
                exec_path[strlen(exec_path) - static_strlen(".manifest")] = '\0';
            } else if (strendswith(exec_path, ".manifest.sgx")) {
                INLINE_SYSCALL(lseek, 3, exec_fd, 0, SEEK_SET);
                manifest_fd = exec_fd;
                exec_fd = -1;

                exec_path[strlen(exec_path) - static_strlen(".manifest.sgx")] = '\0';
            } else {
                SGX_DBG(DBG_E, "Invalid manifest file specified: %s\n", exec_path);
                goto usage;
            }
        }
    } else {
        /* We're one of the children spawned to host new processes started inside Graphene.
         * We'll receive our argv and config via IPC. */
        int parent_pipe_fd = atoi(argv[3]);
        ret = sgx_init_child_process(parent_pipe_fd, &g_pal_enclave.pal_sec);
        if (ret < 0)
            goto out;
        exec_path = strdup(g_pal_enclave.pal_sec.exec_name + URI_PREFIX_FILE_LEN);
        if (!exec_path) {
            ret = -ENOMEM;
            goto out;
        }
        manifest_path = alloc_concat(exec_path, -1, ".manifest.sgx", -1);
        if (!manifest_path) {
            ret = -ENOMEM;
            goto out;
        }
    }

    if (manifest_fd == -1) {
        manifest_fd = INLINE_SYSCALL(open, 3, manifest_path, O_RDONLY | O_CLOEXEC, 0);
        if (IS_ERR(manifest_fd)) {
            SGX_DBG(DBG_E, "Cannot open manifest file: %s\n", manifest_path);
            goto usage;
        }
    }

    SGX_DBG(DBG_I, "Manifest file: %s\n", manifest_path);
    SGX_DBG(DBG_I, "Executable file: %s\n", exec_path);

    /*
     * While C does not guarantee that the argv[i] and envp[i] strings are
     * continuous we know that we are running on Linux, which does this. This
     * saves us creating a copy of all argv and envp strings.
     */
    char* args;
    size_t args_size;
    if (first_process) {
        args = argv[3];
        args_size = argc > 3 ? (argv[argc - 1] - args) + strlen(argv[argc - 1]) + 1 : 0;
    } else {
        args = argv[4];
        args_size = argc > 4 ? (argv[argc - 1] - args) + strlen(argv[argc - 1]) + 1 : 0;
    }

    size_t envc = 0;
    while (envp[envc] != NULL) {
        envc++;
    }
    char* env = envp[0];
    size_t env_size = envc > 0 ? (envp[envc - 1] - envp[0]) + strlen(envp[envc - 1]) + 1 : 0;

    ret = load_enclave(&g_pal_enclave, manifest_fd, manifest_path, exec_path, args, args_size, env,
                       env_size, need_gsgx);
    if (ret < 0) {
        SGX_DBG(DBG_E, "load_enclave() failed with error %d\n", ret);
    }

out:
    if (g_pal_enclave.exec >= 0)
        INLINE_SYSCALL(close, 1, g_pal_enclave.exec);
    if (g_pal_enclave.sigfile >= 0)
        INLINE_SYSCALL(close, 1, g_pal_enclave.sigfile);
    if (g_pal_enclave.token >= 0)
        INLINE_SYSCALL(close, 1, g_pal_enclave.token);
    if (!IS_ERR(exec_fd))
        INLINE_SYSCALL(close, 1, exec_fd);
    if (!IS_ERR(manifest_fd))
        INLINE_SYSCALL(close, 1, manifest_fd);
    free(exec_path);
    free(manifest_path);

    return ret;

usage:;
    const char* self = argv[0] ?: "<this program>";
    printf("USAGE:\n"
           "\tFirst process: %s <path to libpal.so> init [<executable>|<manifest>] args...\n"
           "\tChildren:      %s <path to libpal.so> child <parent_pipe_fd> args...\n",
           self, self);
    printf("This is an internal interface. Use pal_loader to launch applications in Graphene.\n");
    ret = 1;
    goto out;
}
