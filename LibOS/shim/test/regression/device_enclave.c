#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sgx-driver/sgx.h"
#include "sgx_arch.h"

static int g_isgx_device = -1;

static int read_enclave_token(char* token_name, sgx_arch_token_t* token) {
    int token_file = open(token_name, O_RDONLY | O_CLOEXEC, 0);
    if (token_file < 0)
        err(1, "token file open");

    struct stat stat;
    int ret = fstat(token_file, &stat);
    if (ret < 0)
        err(1, "token file fstat");

    int bytes = read(token_file, token, sizeof(sgx_arch_token_t));
    if (bytes < 0)
        err(1, "token file read");

    close(token_file);
    return 0;
}

static int create_enclave(sgx_arch_secs_t* secs, sgx_arch_token_t* token) {
    secs->ssa_frame_size = 2; /* 8192B SSA frame is enough for a dummy enclave */
    secs->misc_select    = token->masked_misc_select_le;
    memcpy(&secs->attributes, &token->body.attributes, sizeof(sgx_attributes_t));

    uint64_t request_mmap_addr = secs->base;
    uint64_t request_mmap_size = secs->size;

    void* addr = mmap((void*)request_mmap_addr, request_mmap_size, PROT_NONE,
                      MAP_FIXED | MAP_SHARED, g_isgx_device, 0);

    if (addr == MAP_FAILED)
        err(1, "enclave initial mmap");

    struct sgx_enclave_create param = {
        .src = (uint64_t)secs,
    };

    int ret = ioctl(g_isgx_device, SGX_IOC_ENCLAVE_CREATE, &param);
    if (ret < 0)
        err(1, "ECREATE ioctl");

    return 0;
}

static int add_tcs_page_to_enclave(sgx_arch_secs_t* secs) {
    int ret;
    uint64_t addr = secs->size - 4096;

    void* zero_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (zero_page == MAP_FAILED)
        err(1, "zero-page mmap");

    sgx_arch_sec_info_t secinfo;
    memset(&secinfo, 0, sizeof(sgx_arch_sec_info_t));
    secinfo.flags |= SGX_SECINFO_FLAGS_TCS;

#ifdef SGX_DCAP_16_OR_LATER
    /* newer DCAP driver (version 1.6+) allows adding a range of pages for performance, use it */
    struct sgx_enclave_add_pages param = {
        .offset  = addr,
        .src     = (uint64_t)zero_page,
        .length  = 4096,
        .secinfo = (uint64_t)&secinfo,
        .flags   = SGX_PAGE_MEASURE,
        .count   = 0,
    };

    while (true) {
        ret = ioctl(g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGES, &param);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            err(1, "ENCLAVE_ADD_PAGES ioctl");
        }
        break;
    }

    void* mapped = mmap((void*)(secs->base + addr), 4096, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_SHARED, g_isgx_device, 0);
    if (mapped == MAP_FAILED)
        err(1, "ENCLAVE_ADD_PAGES mmap");
#else
    /* older drivers (DCAP v1.5- and old out-of-tree) only supports adding one page at a time */
    struct sgx_enclave_add_page param = {
        .addr    = secs->base + addr,
        .src     = (uint64_t)zero_page,
        .secinfo = (uint64_t)&secinfo,
        .mrmask  = (uint16_t)-1,
    };

    while (true) {
        ret = ioctl(g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGE, &param);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            err(1, "ENCLAVE_ADD_PAGE ioctl");
        }
        break;
    }

    ret = mprotect((void*)(secs->base + addr), 4096, PROT_READ | PROT_WRITE);
    if (ret < 0)
        err(1, "ENCLAVE_ADD_PAGE mprotect");
#endif /* SGX_DCAP_16_OR_LATER */

    return 0;
}

int main(int argc, char** argv) {
    int ret;
    sgx_arch_token_t enclave_token;
    sgx_arch_secs_t enclave_secs;

    g_isgx_device = open(ISGX_FILE, O_RDWR | O_CLOEXEC, 0);
    if (g_isgx_device < 0)
        err(1, ISGX_FILE " open");

    char enclave_token_name[256];
    snprintf(enclave_token_name, sizeof(enclave_token_name), "%s.token", argv[0]);
    ret = read_enclave_token(enclave_token_name, &enclave_token);
    if (ret < 0)
        errx(1, "read_enclave_token failed");

    memset(&enclave_secs, 0, sizeof(enclave_secs));
    enclave_secs.base = 1024UL*1024*1024*1024; /* enclave starts at address 1TB */
    enclave_secs.size = 1024UL*1024;           /* enclave size is 1MB */
    ret = create_enclave(&enclave_secs, &enclave_token);
    if (ret < 0)
        errx(1, "create_enclave failed");

    ret = add_tcs_page_to_enclave(&enclave_secs);
    if (ret < 0)
        errx(1, "add_tcs_page_to_enclave failed");

    ret = ioctl(g_isgx_device, 0x00000001, 123);
    if (ret >= 0)
        err(1, "unknown ioctl didn't fail");

    ret = munmap((void*)enclave_secs.base, enclave_secs.size);
    if (ret < 0)
        err(1, "destroy enclave failed");

    puts("TEST OK");
    return 0;
}
