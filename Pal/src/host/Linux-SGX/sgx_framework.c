/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_rtld.h>
#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "sgx-driver/graphene-sgx.h"

#include <asm/errno.h>

int gsgx_device = -1;
int isgx_device = -1;
#define ISGX_FILE "/dev/isgx"

void * zero_page;

int open_gsgx(void)
{
    int fd = INLINE_SYSCALL(open, 3, GSGX_FILE, O_RDWR, 0);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    gsgx_device = fd;

    fd = INLINE_SYSCALL(open, 3, ISGX_FILE, O_RDWR, 0);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    isgx_device = fd;
    
    return 0;
}

int read_enclave_token(int token_file, sgx_arch_token_t * token)
{
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, token_file, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (stat.st_size != sizeof(sgx_arch_token_t)) {
        SGX_DBG(DBG_I, "size of token size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, token_file, token, sizeof(sgx_arch_token_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

    return 0;
}

int read_enclave_sigstruct(int sigfile, sgx_arch_sigstruct_t * sig)
{
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, sigfile, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (stat.st_size < sizeof(sgx_arch_sigstruct_t)) {
        SGX_DBG(DBG_I, "size of sigstruct size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, sigfile, sig, sizeof(sgx_arch_sigstruct_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

    return 0;
}

#define SE_LEAF    0x12

static inline void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t info[4])
{
    asm volatile("cpuid"
                 : "=a"(info[0]),
                   "=b"(info[1]),
                   "=c"(info[2]),
                   "=d"(info[3])
                 : "a"(leaf),
                   "c"(subleaf));
}

static size_t get_ssaframesize (uint64_t xfrm)
{
    uint32_t cpuinfo[4];
    uint64_t xfrm_ex;
    int xsave_size = 0;

    cpuid(SE_LEAF, 1, cpuinfo);
    xfrm_ex = ((uint64_t) cpuinfo[3] << 32) + cpuinfo[2];

    for (int i = 2; i < 64; i++)
        if ((xfrm & (1 << i)) || (xfrm_ex & (1 << i))) {
            cpuid(0xd, i, cpuinfo);
            if (cpuinfo[0] + cpuinfo[1] > xsave_size)
                xsave_size = cpuinfo[0] + cpuinfo[1];
        }

    return ALLOC_ALIGNUP(xsave_size + sizeof(sgx_arch_gpr_t) + 1);
}

int check_wrfsbase_support (void)
{
    if (gsgx_device == -1)
        return -EACCES;

    uint32_t cpuinfo[4];
    cpuid(7, 0, cpuinfo);

    if (!(cpuinfo[1] & 0x1))
        return 0;

    return 1;
}

int create_enclave(sgx_arch_secs_t * secs,
                   unsigned long baseaddr,
                   unsigned long size,
                   sgx_arch_token_t * token)
{
    int flags = MAP_SHARED;
    if (gsgx_device == -1)
        return -EACCES;

    if (!zero_page) {
        zero_page = (void *)
            INLINE_SYSCALL(mmap, 6, NULL, pagesize,
                           PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS,
                           -1, 0);
        if (IS_ERR_P(zero_page))
            return -ENOMEM;
    }

    memset(secs, 0, sizeof(sgx_arch_secs_t));
    secs->size = pagesize;
    while (secs->size < size)
        secs->size <<= 1;
    secs->ssaframesize = get_ssaframesize(token->attributes.xfrm) / pagesize;
    secs->miscselect = token->miscselect_mask;
    memcpy(&secs->attributes, &token->attributes,
           sizeof(sgx_arch_attributes_t));
    memcpy(&secs->mrenclave, &token->mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&secs->mrsigner,  &token->mrsigner,  sizeof(sgx_arch_hash_t));

    struct gsgx_enclave_create param;
    if (baseaddr) {
        secs->baseaddr = (uint64_t) baseaddr & ~(secs->size - 1);
        flags |= MAP_FIXED;
    } else {
        secs->baseaddr = 0ULL;
    }

    uint64_t addr = INLINE_SYSCALL(mmap, 6, secs->baseaddr, size,
                                   PROT_READ|PROT_WRITE|PROT_EXEC, flags,
                                   isgx_device, 0);

    if (IS_ERR_P(addr)) {
        if (ERRNO_P(addr) == 1 && (flags | MAP_FIXED))
            pal_printf("Permission denied on mapping enclave. "
                       "You may need to set sysctl vm.mmap_min_addr to zero\n");

        SGX_DBG(DBG_I, "enclave ECREATE failed in allocating EPC memory "
                "(errno = %d)\n", ERRNO_P(addr));
        return -ENOMEM;
    }

    secs->baseaddr = addr;
    param.src = (uint64_t) secs;
    int ret = INLINE_SYSCALL(ioctl, 3, gsgx_device, GSGX_IOCTL_ENCLAVE_CREATE,
                         &param);
    
    if (IS_ERR(ret)) {
        if (ERRNO(ret) == EBADF)
            gsgx_device = -1;
        SGX_DBG(DBG_I, "enclave ECREATE failed in enclave creation ioctl - %d\n", ERRNO(ret));
        return -ERRNO(ret);
    }

    if (ret) {
        SGX_DBG(DBG_I, "enclave ECREATE failed - %d\n", ret);
        return -EPERM;
    }

    secs->attributes.flags |= SGX_FLAGS_INITIALIZED;

    SGX_DBG(DBG_I, "enclave created:\n");
    SGX_DBG(DBG_I, "    base:         0x%016lx\n", secs->baseaddr);
    SGX_DBG(DBG_I, "    size:         0x%016lx\n", secs->size);
    SGX_DBG(DBG_I, "    attr:         0x%016lx\n", secs->attributes.flags);
    SGX_DBG(DBG_I, "    xfrm:         0x%016lx\n", secs->attributes.xfrm);
    SGX_DBG(DBG_I, "    ssaframesize: %ld\n",      secs->ssaframesize);
    SGX_DBG(DBG_I, "    isvprodid:    0x%08x\n",   secs->isvprodid);
    SGX_DBG(DBG_I, "    isvsvn:       0x%08x\n",   secs->isvsvn);

    return 0;
}

int add_pages_to_enclave(sgx_arch_secs_t * secs,
                         void * addr, void * user_addr,
                         unsigned long size,
                         enum sgx_page_type type, int prot,
                         bool skip_eextend,
                         const char * comment)
{
    if (gsgx_device == -1)
        return -EACCES;

    struct gsgx_enclave_add_pages param;
    sgx_arch_secinfo_t secinfo;

    memset(&secinfo, 0, sizeof(sgx_arch_secinfo_t));

    switch (type) {
        case SGX_PAGE_SECS:
            return -EPERM;
        case SGX_PAGE_TCS:
            secinfo.flags |= SGX_SECINFO_FLAGS_TCS;
            break;
        case SGX_PAGE_REG:
            secinfo.flags |= SGX_SECINFO_FLAGS_REG;
            if (prot & PROT_READ)
                secinfo.flags |= SGX_SECINFO_FLAGS_R;
            if (prot & PROT_WRITE)
                secinfo.flags |= SGX_SECINFO_FLAGS_W;
            if (prot & PROT_EXEC)
                secinfo.flags |= SGX_SECINFO_FLAGS_X;
            break;
    }

    param.addr = secs->baseaddr + (uint64_t) addr;
    param.user_addr = (uint64_t) user_addr;
    param.size = size;
    param.secinfo = (uint64_t) &secinfo;
    param.flags = skip_eextend ? GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND : 0;

    if (!param.user_addr) {
        param.user_addr = (unsigned long) zero_page;
        param.flags |= GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC;
    }

    char p[4] = "---";
    const char * t = (type == SGX_PAGE_TCS) ? "TCS" : "REG";
    const char * m = skip_eextend ? "" : " measured";

    if (type == SGX_PAGE_REG) {
        if (prot & PROT_READ)
            p[0] = 'R';
        if (prot & PROT_WRITE)
            p[1] = 'W';
        if (prot & PROT_EXEC)
            p[2] = 'X';
    }

    if (size == pagesize)
        SGX_DBG(DBG_I, "adding page  to enclave: %016lx [%s:%s] (%s)%s\n",
                addr, t, p, comment, m);
    else
        SGX_DBG(DBG_I, "adding pages to enclave: %016lx-%016lx [%s:%s] (%s)%s\n",
                addr, addr + size, t, p, comment, m);


    int ret = INLINE_SYSCALL(ioctl, 3, gsgx_device,
                             GSGX_IOCTL_ENCLAVE_ADD_PAGES,
                             &param);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_I, "Enclave add page returned %d\n", ret);
        if (ERRNO(ret) == EBADF)
            gsgx_device = -1;
        return -ERRNO(ret);
    }

    return 0;
}

int init_enclave(sgx_arch_secs_t * secs,
                 sgx_arch_sigstruct_t * sigstruct,
                 sgx_arch_token_t * token)
{
    if (gsgx_device == -1)
        return -EACCES;

    unsigned long enclave_valid_addr =
                secs->baseaddr + secs->size - pagesize;

    SGX_DBG(DBG_I, "enclave initializing:\n");
    SGX_DBG(DBG_I, "    enclave id:   0x%016lx\n", enclave_valid_addr);
    SGX_DBG(DBG_I, "    enclave hash:");
    for (int i = 0 ; i < sizeof(sgx_arch_hash_t) ; i++)
        SGX_DBG(DBG_I, " %02x", sigstruct->enclave_hash[i]);
    SGX_DBG(DBG_I, "\n");

    struct gsgx_enclave_init param;
    param.addr = enclave_valid_addr;
    // DEP 11/6/16: I think sigstruct and token are supposed to
    //              be pointers in the new driver
    param.sigstruct = (uint64_t) sigstruct;
    param.einittoken = (uint64_t) token;

    int ret = INLINE_SYSCALL(ioctl, 3, gsgx_device, GSGX_IOCTL_ENCLAVE_INIT,
                             &param);
    if (IS_ERR(ret)) {
        if (ERRNO(ret) == EBADF)
            gsgx_device = -1;
        return -ERRNO(ret);
    }

    if (ret) {
        SGX_DBG(DBG_I, "enclave EINIT failed\n");
        return -EPERM;
    }

    return 0;
}

int destroy_enclave(void * base_addr, size_t length)
{

    SGX_DBG(DBG_I, "destroying enclave...\n");

    int ret = INLINE_SYSCALL(munmap, 2, base_addr, length);

    if (IS_ERR(ret)) {
        SGX_DBG(DBG_I, "enclave EDESTROY failed\n");
        return -ERRNO(ret);
    }

    return 0;
}
