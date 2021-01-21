#include <asm/errno.h>

#include "gsgx.h"
#include "hex.h"
#include "pal_linux.h"
#include "pal_rtld.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"
#include "sgx_log.h"

static int g_gsgx_device = -1;
static int g_isgx_device = -1;

static void* g_zero_pages       = NULL;
static size_t g_zero_pages_size = 0;

int open_sgx_driver(bool need_gsgx) {
    if (need_gsgx) {
        g_gsgx_device = INLINE_SYSCALL(open, 3, GSGX_FILE, O_RDWR | O_CLOEXEC, 0);
        if (IS_ERR(g_gsgx_device)) {
            urts_log_error(
                "\n\tSystem does not support FSGSBASE instructions, which Graphene requires on SGX.\n\n"
                "\tThe best option is to move to a newer Linux kernel with FSGSBASE support (5.9+), or\n"
                "\ta kernel with a back-ported patch to support FSGSBASE.\n"
                "\tOne may also load the Graphene SGX kernel, although this is insecure.\n"
                "\tIf the Graphene SGX module is loaded, check permissions on the device " GSGX_FILE ", as we cannot open this file.\n\n");
            return -ERRNO(g_gsgx_device);
        }
    }

    g_isgx_device = INLINE_SYSCALL(open, 3, ISGX_FILE, O_RDWR | O_CLOEXEC, 0);
    if (IS_ERR(g_isgx_device)) {
        urts_log_error("Cannot open device " ISGX_FILE ". "
                       "Please make sure the Intel SGX kernel module is loaded.\n");
        if (need_gsgx) {
            INLINE_SYSCALL(close, 1, g_gsgx_device);
            g_gsgx_device = -1;
        }
        return -ERRNO(g_isgx_device);
    }

    return 0;
}

int read_enclave_token(int token_file, sgx_arch_token_t* token) {
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, token_file, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if (stat.st_size != sizeof(sgx_arch_token_t)) {
        urts_log_error("size of token size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, token_file, token, sizeof(sgx_arch_token_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

#ifdef SGX_DCAP
    urts_log_debug("Read dummy DCAP token\n");
#else
    urts_log_debug("Read token:\n");
    urts_log_debug("    valid:                 0x%08x\n",   token->body.valid);
    urts_log_debug("    attr.flags:            0x%016lx\n", token->body.attributes.flags);
    urts_log_debug("    attr.xfrm:             0x%016lx\n", token->body.attributes.xfrm);
    urts_log_debug("    mr_enclave:            %s\n",
                   ALLOCA_BYTES2HEXSTR(token->body.mr_enclave.m));
    urts_log_debug("    mr_signer:             %s\n", ALLOCA_BYTES2HEXSTR(token->body.mr_signer.m));
    urts_log_debug("    LE cpu_svn:            %s\n", ALLOCA_BYTES2HEXSTR(token->cpu_svn_le.svn));
    urts_log_debug("    LE isv_prod_id:        %02x\n", token->isv_prod_id_le);
    urts_log_debug("    LE isv_svn:            %02x\n", token->isv_svn_le);
    urts_log_debug("    LE masked_misc_select: 0x%08x\n",   token->masked_misc_select_le);
    urts_log_debug("    LE attr.flags:         0x%016lx\n", token->attributes_le.flags);
    urts_log_debug("    LE attr.xfrm:          0x%016lx\n", token->attributes_le.xfrm);
#endif

    return 0;
}

int read_enclave_sigstruct(int sigfile, sgx_arch_enclave_css_t* sig) {
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, sigfile, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if ((size_t)stat.st_size != sizeof(sgx_arch_enclave_css_t)) {
        urts_log_error("size of sigstruct size does not match\n");
        return -EINVAL;
    }

    int bytes = INLINE_SYSCALL(read, 3, sigfile, sig, sizeof(sgx_arch_enclave_css_t));
    if (IS_ERR(bytes))
        return -ERRNO(bytes);

    return 0;
}

static size_t get_ssaframesize(uint64_t xfrm) {
    uint32_t cpuinfo[4];
    uint64_t xfrm_ex;
    size_t xsave_size = 0;

    cpuid(INTEL_SGX_LEAF, 1, cpuinfo);
    xfrm_ex = ((uint64_t)cpuinfo[3] << 32) + cpuinfo[2];

    for (int i = 2; i < 64; i++)
        if ((xfrm & (1ULL << i)) || (xfrm_ex & (1ULL << i))) {
            cpuid(0xd, i, cpuinfo);
            if (cpuinfo[0] + cpuinfo[1] > xsave_size)
                xsave_size = cpuinfo[0] + cpuinfo[1];
        }

    return ALLOC_ALIGN_UP(xsave_size + sizeof(sgx_pal_gpr_t) + 1);
}

bool is_wrfsbase_supported(void) {
    uint32_t cpuinfo[4];
    cpuid(7, 0, cpuinfo);

    if (!(cpuinfo[1] & 0x1)) {
        urts_log_error(
            "The WRFSBASE instruction is not permitted on this platform. Please make sure the "
            "Graphene SGX kernel module is loaded properly.\n");
        return false;
    }

    return true;
}

int create_enclave(sgx_arch_secs_t* secs, sgx_arch_token_t* token) {
    assert(secs->size && IS_POWER_OF_2(secs->size));
    assert(IS_ALIGNED(secs->base, secs->size));

    secs->ssa_frame_size = get_ssaframesize(token->body.attributes.xfrm) / g_page_size;
    secs->misc_select    = token->masked_misc_select_le;
    memcpy(&secs->attributes, &token->body.attributes, sizeof(sgx_attributes_t));

    /* Do not initialize secs->mr_signer and secs->mr_enclave here as they are
     * not used by ECREATE to populate the internal SECS. SECS's mr_enclave is
     * computed dynamically and SECS's mr_signer is populated based on the
     * SIGSTRUCT during EINIT (see pp21 for ECREATE and pp34 for
     * EINIT in https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf). */

    uint64_t request_mmap_addr = secs->base;
    uint64_t request_mmap_size = secs->size;

#ifdef SGX_DCAP
    /* newer DCAP/in-kernel SGX drivers allow starting enclave address space with non-zero;
     * the below trick to start from MMAP_MIN_ADDR is to avoid vm.mmap_min_addr==0 issue */
    if (request_mmap_addr < MMAP_MIN_ADDR) {
        request_mmap_size -= MMAP_MIN_ADDR - request_mmap_addr;
        request_mmap_addr  = MMAP_MIN_ADDR;
    }
#endif

    uint64_t addr = INLINE_SYSCALL(mmap, 6, request_mmap_addr, request_mmap_size,
                                   PROT_NONE, /* newer DCAP driver requires such initial mmap */
#ifdef SGX_DCAP
                                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
                                   MAP_FIXED | MAP_SHARED, g_isgx_device, 0);
#endif

    if (IS_ERR_P(addr)) {
        if (ERRNO_P(addr) == EPERM) {
            pal_printf("Permission denied on mapping enclave. "
                       "You may need to set sysctl vm.mmap_min_addr to zero\n");
        }

        urts_log_error("ECREATE failed in allocating EPC memory (errno = %ld)\n", ERRNO_P(addr));
        return -ENOMEM;
    }

    assert(addr == request_mmap_addr);

    struct sgx_enclave_create param = {
        .src = (uint64_t)secs,
    };
    int ret = INLINE_SYSCALL(ioctl, 3, g_isgx_device, SGX_IOC_ENCLAVE_CREATE, &param);

    if (IS_ERR(ret)) {
        urts_log_error("ECREATE failed in enclave creation ioctl (errno = %d)\n", ERRNO(ret));
        return -ERRNO(ret);
    }

    if (ret) {
        urts_log_error("ECREATE failed (errno = %d)\n", ret);
        return -EPERM;
    }

    secs->attributes.flags |= SGX_FLAGS_INITIALIZED;

    urts_log_debug("enclave created:\n");
    urts_log_debug("    base:           0x%016lx\n", secs->base);
    urts_log_debug("    size:           0x%016lx\n", secs->size);
    urts_log_debug("    misc_select:    0x%08x\n",   secs->misc_select);
    urts_log_debug("    attr.flags:     0x%016lx\n", secs->attributes.flags);
    urts_log_debug("    attr.xfrm:      0x%016lx\n", secs->attributes.xfrm);
    urts_log_debug("    ssa_frame_size: %d\n",       secs->ssa_frame_size);
    urts_log_debug("    isv_prod_id:    0x%08x\n",   secs->isv_prod_id);
    urts_log_debug("    isv_svn:        0x%08x\n",   secs->isv_svn);

    return 0;
}

int add_pages_to_enclave(sgx_arch_secs_t* secs, void* addr, void* user_addr, unsigned long size,
                         enum sgx_page_type type, int prot, bool skip_eextend,
                         const char* comment) {
    __UNUSED(secs); /* Used only under DCAP ifdefs */
    sgx_arch_sec_info_t secinfo;
    int ret;

    if (!g_zero_pages) {
        /* initialize with just one page */
        g_zero_pages = (void*)INLINE_SYSCALL(mmap, 6, NULL, g_page_size, PROT_READ,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_ERR_P(g_zero_pages)) {
            urts_log_error("Cannot mmap zero pages %ld\n", ERRNO_P(g_zero_pages));
            return -ENOMEM;
        }
        g_zero_pages_size = g_page_size;
    }

    memset(&secinfo, 0, sizeof(sgx_arch_sec_info_t));

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

    char p[4] = "---";
    const char* t = (type == SGX_PAGE_TCS) ? "TCS" : "REG";
    const char* m = skip_eextend ? "" : " measured";

    if (type == SGX_PAGE_REG) {
        if (prot & PROT_READ)
            p[0] = 'R';
        if (prot & PROT_WRITE)
            p[1] = 'W';
        if (prot & PROT_EXEC)
            p[2] = 'X';
    }

    if (size == g_page_size)
        urts_log_debug("adding page  to enclave: %p [%s:%s] (%s)%s\n", addr, t, p, comment, m);
    else
        urts_log_debug("adding pages to enclave: %p-%p [%s:%s] (%s)%s\n", addr, addr + size, t, p,
                      comment, m);

#ifdef SGX_DCAP
    if (!user_addr && g_zero_pages_size < size) {
        /* not enough contigious zero pages to back up enclave pages, allocate more */
        /* TODO: this logic can be removed if we introduce a size cap in ENCLAVE_ADD_PAGES ioctl */
        ret = INLINE_SYSCALL(munmap, 2, g_zero_pages, g_zero_pages_size);
        if (IS_ERR(ret)) {
            urts_log_error("Cannot unmap zero pages %d\n", ret);
            return -ERRNO(ret);
        }

        g_zero_pages = (void*)INLINE_SYSCALL(mmap, 6, NULL, size, PROT_READ,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_ERR_P(g_zero_pages)) {
            urts_log_error("Cannot map zero pages %ld\n", ERRNO_P(g_zero_pages));
            return -ENOMEM;
        }
        g_zero_pages_size = size;
    }

    /* newer DCAP driver (version 1.6+) allows adding a range of pages for performance, use it */
    struct sgx_enclave_add_pages param = {
        .offset  = (uint64_t)addr - secs->base,
        .src     = (uint64_t)(user_addr ?: g_zero_pages),
        .length  = size,
        .secinfo = (uint64_t)&secinfo,
        .flags   = skip_eextend ? 0 : SGX_PAGE_MEASURE,
        .count   = 0, /* output parameter, will be checked after IOCTL */
    };
    /* DCAP and in-kernel drivers require aligned data */
    assert(IS_ALIGNED_POW2(param.src, g_page_size));
    assert(IS_ALIGNED_POW2(param.offset, g_page_size));

    /* NOTE: SGX driver v39 removes `count` field and returns "number of bytes added" as return
     * value directly in `ret`. It also caps the maximum number of bytes to be added as 1MB, or 256
     * enclave pages. Thus, the below code must loop on the ADD_PAGES ioctl until all pages are
     * added; the code must first check `ret > 0` and only then check `count` field to support all
     * versions of the SGX driver. Note that even though `count` is removed in v39, it is the last
     * field of struct and thus may stay redundant (and unused by driver v39). We hope that this
     * contrived logic won't be needed when the SGX driver stabilizes its ioctl interface.
     * (https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/linux-sgx.git/tag/?h=v39) */
    while (param.length > 0) {
        ret = INLINE_SYSCALL(ioctl, 3, g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGES, &param);
        if (IS_ERR(ret)) {
            if (ret == -EINTR)
                continue;
            urts_log_error("Enclave EADD returned %d\n", ret);
            return -ERRNO(ret);
        }

        uint64_t added_size = ret > 0 ? (uint64_t)ret : param.count;
        if (!added_size) {
            urts_log_error("Intel SGX driver did not perform EADD. This may indicate a buggy "
                           "driver, please update to the most recent version.\n");
            return -EPERM;
        }

        param.offset += added_size;
        if (param.src != (uint64_t)g_zero_pages)
            param.src += added_size;
        param.length -= added_size;
    }

    /* ask Intel SGX driver to actually mmap the added enclave pages */
    uint64_t mapped = INLINE_SYSCALL(mmap, 6, addr, size, prot, MAP_FIXED | MAP_SHARED,
                                     g_isgx_device, 0);
    if (IS_ERR_P(mapped)) {
        urts_log_error("Cannot map enclave pages %ld\n", ERRNO_P(mapped));
        return -EACCES;
    }
#else
    /* older drivers (DCAP v1.5- and old out-of-tree) only supports adding one page at a time */
    struct sgx_enclave_add_page param = {
        .addr    = (uint64_t)addr,
        .src     = (uint64_t)(user_addr ?: g_zero_pages),
        .secinfo = (uint64_t)&secinfo,
        .mrmask  = skip_eextend ? 0 : (uint16_t)-1,
    };

    uint64_t added_size = 0;
    while (added_size < size) {
        ret = INLINE_SYSCALL(ioctl, 3, g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGE, &param);
        if (IS_ERR(ret)) {
            if (ret == -EINTR)
                continue;
            urts_log_error("Enclave EADD returned %d\n", ret);
            return -ERRNO(ret);
        }

        param.addr += g_page_size;
        if (param.src != (uint64_t)g_zero_pages)
            param.src += g_page_size;
        added_size += g_page_size;
    }

    /* need to change permissions for EADDed pages since the initial mmap was with PROT_NONE */
    ret = mprotect(addr, size, prot);
    if (IS_ERR(ret)) {
        urts_log_error("Changing protections of EADDed pages returned %d\n", ret);
        return -ERRNO(ret);
    }
#endif /* SGX_DCAP */

    return 0;
}

int init_enclave(sgx_arch_secs_t* secs, sgx_arch_enclave_css_t* sigstruct,
                 sgx_arch_token_t* token) {
#ifdef SGX_DCAP
    __UNUSED(token);
#endif
    unsigned long enclave_valid_addr = secs->base + secs->size - g_page_size;

    urts_log_debug("enclave initializing:\n");
    urts_log_debug("    enclave id:   0x%016lx\n", enclave_valid_addr);
    urts_log_debug("    mr_enclave:   %s\n", ALLOCA_BYTES2HEXSTR(sigstruct->body.enclave_hash.m));

    struct sgx_enclave_init param = {
#ifndef SGX_DCAP
        .addr = enclave_valid_addr,
#endif
        .sigstruct = (uint64_t)sigstruct,
#ifndef SGX_DCAP
        .einittoken = (uint64_t)token,
#endif
    };
    int ret = INLINE_SYSCALL(ioctl, 3, g_isgx_device, SGX_IOC_ENCLAVE_INIT, &param);

    if (IS_ERR(ret)) {
        return -ERRNO(ret);
    }

    if (ret) {
        const char* error;
        /* DEP 3/22/17: Try to improve error messages */
        switch (ret) {
            case SGX_INVALID_SIG_STRUCT:
                error = "Invalid SIGSTRUCT";
                break;
            case SGX_INVALID_ATTRIBUTE:
                error = "Invalid enclave attribute";
                break;
            case SGX_INVALID_MEASUREMENT:
                error = "Invalid measurement";
                break;
            case SGX_INVALID_SIGNATURE:
                error = "Invalid signature";
                break;
            case SGX_INVALID_LICENSE:
                error = "Invalid EINIT token";
                break;
            case SGX_INVALID_CPUSVN:
                error = "Invalid CPU SVN";
                break;
            default:
                error = "Unknown reason";
                break;
        }
        urts_log_error("enclave EINIT failed - %s\n", error);
        return -EPERM;
    }

    /* all enclave pages were EADDed, don't need zero pages anymore */
    ret = INLINE_SYSCALL(munmap, 2, g_zero_pages, g_zero_pages_size);
    if (IS_ERR(ret)) {
        urts_log_error("Cannot unmap zero pages %d\n", ret);
        return -ERRNO(ret);
    }

    return 0;
}

int destroy_enclave(void* base_addr, size_t length) {
    urts_log_debug("destroying enclave...\n");

    int ret = INLINE_SYSCALL(munmap, 2, base_addr, length);

    if (IS_ERR(ret)) {
        urts_log_error("enclave EDESTROY failed\n");
        return -ERRNO(ret);
    }

    return 0;
}
