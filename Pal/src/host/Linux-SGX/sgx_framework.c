#include <pal_linux.h>
#include <pal_rtld.h>
#include <pal_crypto.h>
#include <hex.h>

#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "sgx_attest.h"
#include "graphene-sgx.h"
#include "quote/aesm.pb-c.h"

#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/un.h>
#define __USE_XOPEN2K8
#include <stdlib.h>

int gsgx_device = -1;
int isgx_device = -1;
#define ISGX_FILE "/dev/isgx"

void * zero_page;

int open_gsgx(void)
{
    gsgx_device = INLINE_SYSCALL(open, 3, GSGX_FILE, O_RDWR, 0);
    if (IS_ERR(gsgx_device)) {
        SGX_DBG(DBG_E, "Cannot open device " GSGX_FILE ". Please make sure the"
                " \'graphene_sgx\' kernel module is loaded.\n");
        return -ERRNO(gsgx_device);
    }

    isgx_device = INLINE_SYSCALL(open, 3, ISGX_FILE, O_RDWR, 0);
    if (IS_ERR(isgx_device)) {
        SGX_DBG(DBG_E, "Cannot open device " ISGX_FILE ". Please make sure the"
                " Intel SGX kernel module is loaded.\n");
        return -ERRNO(isgx_device);
    }

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

    SGX_DBG(DBG_I, "read token:\n");
    SGX_DBG(DBG_I, "    valid:        0x%08x\n", token->valid);
    SGX_DBG(DBG_I, "    attr:         0x%016lx\n", token->attributes.flags);
    SGX_DBG(DBG_I, "    xfrm:         0x%016lx\n", token->attributes.xfrm);
    SGX_DBG(DBG_I, "    miscmask:     0x%08x\n",   token->miscselect_mask);
    SGX_DBG(DBG_I, "    attr_mask:    0x%016lx\n", token->attribute_mask.flags);
    SGX_DBG(DBG_I, "    xfrm_mask:    0x%016lx\n", token->attribute_mask.xfrm);

    return 0;
}

int read_enclave_sigstruct(int sigfile, sgx_arch_sigstruct_t * sig)
{
    struct stat stat;
    int ret;
    ret = INLINE_SYSCALL(fstat, 2, sigfile, &stat);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    if ((size_t)stat.st_size < sizeof(sgx_arch_sigstruct_t)) {
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
    __asm__ volatile("cpuid"
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
    size_t xsave_size = 0;

    cpuid(SE_LEAF, 1, cpuinfo);
    xfrm_ex = ((uint64_t) cpuinfo[3] << 32) + cpuinfo[2];

    for (int i = 2; i < 64; i++)
        if ((xfrm & (1ULL << i)) || (xfrm_ex & (1ULL << i))) {
            cpuid(0xd, i, cpuinfo);
            if (cpuinfo[0] + cpuinfo[1] > xsave_size)
                xsave_size = cpuinfo[0] + cpuinfo[1];
        }

    return ALLOC_ALIGNUP(xsave_size + sizeof(sgx_arch_gpr_t) + 1);
}

bool is_wrfsbase_supported (void)
{
    uint32_t cpuinfo[4];
    cpuid(7, 0, cpuinfo);

    if (!(cpuinfo[1] & 0x1)) {
        SGX_DBG(DBG_E, "The WRFSBASE instruction is not permitted on this"
                " platform. Please make sure the \'graphene_sgx\' kernel module"
                " is loaded properly.\n");
        return false;
    }

    return true;
}

int create_enclave(sgx_arch_secs_t * secs,
                   unsigned long baseaddr,
                   unsigned long size,
                   sgx_arch_token_t * token)
{
    int flags = MAP_SHARED;

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
    /* Do not initialize secs->mrsigner and secs->mrenclave here as they are
     * not used by ECREATE to populate the internal SECS. SECS's mrenclave is
     * computed dynamically and SECS's mrsigner is populated based on the
     * SIGSTRUCT during EINIT (see pp21 for ECREATE and pp34 for
     * EINIT in https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf). */

    if (baseaddr) {
        secs->baseaddr = (uint64_t) baseaddr & ~(secs->size - 1);
    } else {
        secs->baseaddr = ENCLAVE_HIGH_ADDRESS;
    }

    uint64_t addr = INLINE_SYSCALL(mmap, 6, secs->baseaddr, secs->size,
                                   PROT_READ|PROT_WRITE|PROT_EXEC,
                                   flags|MAP_FIXED, isgx_device, 0);

    if (IS_ERR_P(addr)) {
        if (ERRNO_P(addr) == 1 && (flags | MAP_FIXED))
            pal_printf("Permission denied on mapping enclave. "
                       "You may need to set sysctl vm.mmap_min_addr to zero\n");

        SGX_DBG(DBG_I, "enclave ECREATE failed in allocating EPC memory "
                "(errno = %ld)\n", ERRNO_P(addr));
        return -ENOMEM;
    }

    secs->baseaddr = addr;

#if SDK_DRIVER_VERSION >= KERNEL_VERSION(1, 8, 0)
    struct sgx_enclave_create param = {
        .src = (uint64_t) secs,
    };
    int ret = INLINE_SYSCALL(ioctl, 3, isgx_device, SGX_IOC_ENCLAVE_CREATE,
                         &param);
#else
    struct gsgx_enclave_create param = {
        .src = (uint64_t) secs,
    };
    int ret = INLINE_SYSCALL(ioctl, 3, gsgx_device, GSGX_IOCTL_ENCLAVE_CREATE,
                         &param);
#endif

    if (IS_ERR(ret)) {
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
    SGX_DBG(DBG_I, "    miscselect:   0x%08x\n",   secs->miscselect);
    SGX_DBG(DBG_I, "    attr:         0x%016lx\n", secs->attributes.flags);
    SGX_DBG(DBG_I, "    xfrm:         0x%016lx\n", secs->attributes.xfrm);
    SGX_DBG(DBG_I, "    ssaframesize: %d\n",       secs->ssaframesize);
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
    sgx_arch_secinfo_t secinfo;
    int ret;

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
        SGX_DBG(DBG_I, "adding page  to enclave: %p [%s:%s] (%s)%s\n",
                addr, t, p, comment, m);
    else
        SGX_DBG(DBG_I, "adding pages to enclave: %p-%p [%s:%s] (%s)%s\n",
                addr, addr + size, t, p, comment, m);


#if SDK_DRIVER_VERSION >= KERNEL_VERSION(1, 8, 0)
    struct sgx_enclave_add_page param = {
        .addr       = secs->baseaddr + (uint64_t) addr,
        .src        = (uint64_t) (user_addr ? : zero_page),
        .secinfo    = (uint64_t) &secinfo,
        .mrmask     = skip_eextend ? 0 : (uint16_t) -1,
    };

    uint64_t added_size = 0;
    while (added_size < size) {
        ret = INLINE_SYSCALL(ioctl, 3, isgx_device,
                             SGX_IOC_ENCLAVE_ADD_PAGE, &param);
        if (IS_ERR(ret)) {
            SGX_DBG(DBG_I, "Enclave add page returned %d\n", ret);
            return -ERRNO(ret);
        }

        param.addr += pagesize;
        if (param.src != (uint64_t) zero_page) param.src += pagesize;
        added_size += pagesize;
    }
#else
    struct gsgx_enclave_add_pages param = {
        .addr       = secs->baseaddr + (uint64_t) addr,
        .user_addr  = (uint64_t) user_addr,
        .size       = size,
        .secinfo    = (uint64_t) &secinfo,
        .flags      = skip_eextend ? GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND : 0,
    };

    if (!user_addr) {
        param.user_addr = (unsigned long) zero_page;
        param.flags |= GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC;
    }

    ret = INLINE_SYSCALL(ioctl, 3, gsgx_device,
                         GSGX_IOCTL_ENCLAVE_ADD_PAGES,
                         &param);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_I, "Enclave add page returned %d\n", ret);
        return -ERRNO(ret);
    }
#endif

    return 0;
}

int init_enclave(sgx_arch_secs_t * secs,
                 sgx_arch_sigstruct_t * sigstruct,
                 sgx_arch_token_t * token)
{
    unsigned long enclave_valid_addr =
                secs->baseaddr + secs->size - pagesize;

    SGX_DBG(DBG_I, "enclave initializing:\n");
    SGX_DBG(DBG_I, "    enclave id:   0x%016lx\n", enclave_valid_addr);
    SGX_DBG(DBG_I, "    enclave hash:");
    for (size_t i = 0 ; i < sizeof(sgx_arch_hash_t) ; i++)
        SGX_DBG(DBG_I, " %02x", sigstruct->enclave_hash[i]);
    SGX_DBG(DBG_I, "\n");

#if SDK_DRIVER_VERSION >= KERNEL_VERSION(1, 8, 0)
    struct sgx_enclave_init param = {
        .addr           = enclave_valid_addr,
        .sigstruct      = (uint64_t) sigstruct,
        .einittoken     = (uint64_t) token,
    };
    int ret = INLINE_SYSCALL(ioctl, 3, isgx_device, SGX_IOC_ENCLAVE_INIT,
                             &param);
#else
    struct gsgx_enclave_init param = {
        .addr           = enclave_valid_addr,
        .sigstruct      = (uint64_t) sigstruct,
        .einittoken     = (uint64_t) token,
    };
    int ret = INLINE_SYSCALL(ioctl, 3, gsgx_device, GSGX_IOCTL_ENCLAVE_INIT,
                             &param);
#endif

    if (IS_ERR(ret)) {
        return -ERRNO(ret);
    }

    if (ret) {
        const char * error;
        /* DEP 3/22/17: Try to improve error messages */
        switch(ret) {
        case SGX_INVALID_SIG_STRUCT:
            error = "Invalid SIGSTRUCT";          break;
        case SGX_INVALID_ATTRIBUTE:
            error = "Invalid enclave attribute";  break;
        case SGX_INVALID_MEASUREMENT:
            error = "Invalid measurement";        break;
        case SGX_INVALID_SIGNATURE:
            error = "Invalid signature";          break;
        case SGX_INVALID_LICENSE:
            error = "Invalid EINIT token";        break;
        case SGX_INVALID_CPUSVN:
            error = "Invalid CPU SVN";            break;
        default:
            error = "Unknown reason";             break;
        }
        SGX_DBG(DBG_I, "enclave EINIT failed - %s\n", error);
        return -EPERM;
    }

    return 0;
}

static int connect_aesm_service(void) {
    int sock = INLINE_SYSCALL(socket, 3, AF_UNIX, SOCK_STREAM, 0);
    if (IS_ERR(sock))
        return -ERRNO(sock);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy_static(addr.sun_path, "\0sgx_aesm_socket_base", sizeof(addr.sun_path));

    int ret = INLINE_SYSCALL(connect, 3, sock, &addr, sizeof(addr));
    if (!IS_ERR(ret))
        return sock;
    if (ERRNO(ret) != ECONNREFUSED)
        goto err;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy_static(addr.sun_path, "/var/run/aesmd/aesm.socket", sizeof(addr.sun_path));

    ret = INLINE_SYSCALL(connect, 3, sock, &addr, sizeof(addr));
    if (!IS_ERR(ret))
        return sock;

err:
    INLINE_SYSCALL(close, 1, sock);
    return -ERRNO(ret);
}

static int request_aesm_service(Request* req, Response** res) {

    int aesm_socket = connect_aesm_service();
    if (aesm_socket < 0)
        return aesm_socket;

    uint32_t req_len = (uint32_t) request__get_packed_size(req);
    uint8_t* req_buf = __alloca(req_len);
    request__pack(req, req_buf);

    int ret = INLINE_SYSCALL(write, 3, aesm_socket, &req_len, sizeof(req_len));
    if (IS_ERR(ret))
        goto err;

    ret = INLINE_SYSCALL(write, 3, aesm_socket, req_buf, req_len);
    if (IS_ERR(ret))
        goto err;

    uint32_t res_len;
    ret = INLINE_SYSCALL(read, 3, aesm_socket, &res_len, sizeof(res_len));
    if (IS_ERR(ret))
        goto err;

    uint8_t* res_buf = __alloca(res_len);
    ret = INLINE_SYSCALL(read, 3, aesm_socket, res_buf, res_len);
    if (IS_ERR(ret))
        goto err;

    *res = response__unpack(NULL, res_len, res_buf);
    ret = *res == NULL ? -EINVAL : 0;
err:
    INLINE_SYSCALL(close, 1, aesm_socket);
    return -ERRNO(ret);
}

int init_aesm_targetinfo(sgx_arch_targetinfo_t* aesm_targetinfo) {

    Request req = REQUEST__INIT;
    Request__InitQuoteRequest initreq = REQUEST__INIT_QUOTE_REQUEST__INIT;
    req.initquotereq = &initreq;

    Response* res = NULL;
    int ret = request_aesm_service(&req, &res);
    if (ret < 0)
        return ret;

    ret = -EPERM;
    if (!res->initquoteres) {
        SGX_DBG(DBG_E, "aesm_service returned wrong message\n");
        goto failed;
    }

    Response__InitQuoteResponse* r = res->initquoteres;
    if (r->errorcode != 0) {
        SGX_DBG(DBG_E, "aesm_service returned error: %d\n", r->errorcode);
        goto failed;
    }

    if (r->targetinfo.len != sizeof(*aesm_targetinfo)) {
        SGX_DBG(DBG_E, "aesm_service returned invalid target info\n");
        goto failed;
    }

    memcpy(aesm_targetinfo, r->targetinfo.data, sizeof(*aesm_targetinfo));
    ret = 0;
failed:
    response__free_unpacked(res, NULL);
    return ret;
}

/*
 * Contact to Intel Attestation Service and retrieve the signed attestation report
 * @nonce:       Random nonce generated in the enclave.
 * @quote:       Platform quote retrieved from AESMD.
 * @attestation: Attestation data to be returned to the enclave.
 */
int contact_intel_attest_service(const sgx_quote_nonce_t* nonce, const sgx_quote_t* quote,
                                 sgx_attestation_t* attestation) {

    if (!current_enclave->ra_cert ||
        !current_enclave->ra_pkey) {
        SGX_DBG(DBG_E, "Need both certificate and private key for contacting IAS\n");
        return -PAL_ERROR_DENIED;
    }

    size_t quote_len = sizeof(sgx_quote_t) + quote->sig_len;
    size_t quote_str_len;
    lib_Base64Encode((uint8_t*)quote, quote_len, NULL, &quote_str_len);
    char* quote_str = __alloca(quote_str_len);
    int ret = lib_Base64Encode((uint8_t*)quote, quote_len, quote_str, &quote_str_len);
    if (ret < 0)
        return ret;

    size_t nonce_str_len = sizeof(sgx_quote_nonce_t) * 2 + 1;
    char* nonce_str = __alloca(nonce_str_len);
    __bytes2hexstr((void *)nonce, sizeof(sgx_quote_nonce_t), nonce_str, nonce_str_len);

    // Create two temporary files for dumping the header and output of HTTPS request to IAS
    char    https_header_path[] = "gsgx-ias-header-XXXXXX";
    char    https_output_path[] = "gsgx-ias-output-XXXXXX";
    char*   https_header = NULL;
    char*   https_output = NULL;
    ssize_t https_header_len = 0;
    ssize_t https_output_len = 0;
    int header_fd = -1;
    int output_fd = -1;
    int pipefds[2] = { -1, -1 };

    header_fd = mkstemp(https_header_path);
    if (header_fd < 0)
        goto failed;

    output_fd = mkstemp(https_output_path);
    if (output_fd < 0)
        goto failed;

    ret = INLINE_SYSCALL(pipe, 1, pipefds);
    if (IS_ERR(ret))
        goto failed;

    // Write HTTPS request in XML format
    size_t https_request_len = quote_str_len + nonce_str_len + HTTPS_REQUEST_MAX_LENGTH;
    char*  https_request = __alloca(https_request_len);
    https_request_len = snprintf(https_request, https_request_len,
                                 "{\"isvEnclaveQuote\":\"%s\",\"nonce\":\"%s\"}",
                                 quote_str, nonce_str);

    ret = INLINE_SYSCALL(write, 3, pipefds[1], https_request, https_request_len);
    if (IS_ERR(ret))
        goto failed;
    INLINE_SYSCALL(close, 1, pipefds[1]);
    pipefds[1] = -1;

    // Start a HTTPS client (using CURL)
    const char* https_client_args[] = {
            "/usr/bin/curl", "-s", "--tlsv1.2", "-X", "POST",
            "-H", "Content-Type: application/json",
            "--cert", current_enclave->ra_cert,
            "--key",  current_enclave->ra_pkey,
            "--data", "@-", "-o", https_output_path, "-D", https_header_path,
            IAS_TEST_REPORT_URL, NULL,
        };

    int pid = ARCH_VFORK();
    if (IS_ERR(pid))
        goto failed;

    if (!pid) {
        INLINE_SYSCALL(dup2, 2, pipefds[0], 0);
        extern char** environ;
        INLINE_SYSCALL(execve, 3, https_client_args[0], https_client_args, environ);

        /* shouldn't get to here */
        SGX_DBG(DBG_E, "unexpected failure of new process\n");
        __asm__ volatile ("hlt");
        return 0;
    }

    // Make sure the HTTPS client has exited properly
    int status;
    ret = INLINE_SYSCALL(wait4, 4, pid, &status, 0, NULL);
    if (IS_ERR(ret) || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto failed;

    // Read the HTTPS output
    ret = INLINE_SYSCALL(open, 2, https_output_path, O_RDONLY);
    if (IS_ERR(ret))
        goto failed;
    INLINE_SYSCALL(close, 1, output_fd);
    output_fd = ret;
    https_output_len = INLINE_SYSCALL(lseek, 3, output_fd, 0, SEEK_END);
    if (IS_ERR(https_output_len) || !https_output_len)
        goto failed;
    https_output = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(https_output_len),
                                         PROT_READ, MAP_PRIVATE|MAP_FILE, output_fd, 0);
    if (IS_ERR_P(https_output))
        goto failed;

    // Read the HTTPS headers
    ret = INLINE_SYSCALL(open, 2, https_header_path, O_RDONLY);
    if (IS_ERR(ret))
        goto failed;
    INLINE_SYSCALL(close, 1, header_fd);
    header_fd = ret;
    https_header_len = INLINE_SYSCALL(lseek, 3, header_fd, 0, SEEK_END);
    if (IS_ERR(https_header_len) || !https_header_len)
        goto failed;
    https_header = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(https_header_len),
                                         PROT_READ, MAP_PRIVATE|MAP_FILE, header_fd, 0);
    if (IS_ERR_P(https_header))
        goto failed;

    // Parse the HTTPS headers
    size_t   ias_sig_len     = 0;
    uint8_t* ias_sig         = NULL;
    size_t   ias_certs_len   = 0;
    char*    ias_certs       = NULL;
    char*    start       = https_header;
    char*    end         = strchr(https_header, '\n');
    while (end) {
        char* next_start = end + 1;
        // If the eol (\n) is preceded by a return (\r), move the end pointer.
        if (end > start + 1 && *(end - 1) == '\r')
            end--;

        if (strpartcmp_static(start, "x-iasreport-signature: ")) {
            start += static_strlen("x-iasreport-signature: ");

            // Decode IAS report signature
            ret = lib_Base64Decode(start, end - start, NULL, &ias_sig_len);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Malformed IAS signature\n");
                goto failed;
            }

            ias_sig = (uint8_t*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(ias_sig_len),
                                               PROT_READ|PROT_WRITE,
                                               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (IS_ERR_P(ias_sig)) {
                SGX_DBG(DBG_E, "Cannot allocate memory for IAS report signature\n");
                goto failed;
            }

            ret = lib_Base64Decode(start, end - start, ias_sig, &ias_sig_len);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Malformed IAS report signature\n");
                goto failed;
            }
        } else if (strpartcmp_static(start, "x-iasreport-signing-certificate: ")) {
            start += static_strlen("x-iasreport-signing-certificate: ");

            // Decode IAS signature chain
            ias_certs_len = end - start;
            ias_certs = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(ias_certs_len),
                                              PROT_READ|PROT_WRITE,
                                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (IS_ERR_P(ias_certs)) {
                SGX_DBG(DBG_E, "Cannot allocate memory for IAS certificate chain\n");
                goto failed;
            }

            size_t total_bytes = 0;
            // Covert escaped characters
            for (size_t i = 0; i < ias_certs_len; i++) {
                if (start[i] == '%') {
                    int8_t hex1 = hex2dec(start[i + 1]), hex2 = hex2dec(start[i + 2]);
                    if (hex1 < 0 || hex2 < 0)
                        goto failed;

                    char c = hex1 * 16 + hex2;
                    if (c != '\n') ias_certs[total_bytes++] = c;
                    i += 2;
                } else {
                    ias_certs[total_bytes++] = start[i];
                }
            }

            // Adjust certificate chain length
            ias_certs[total_bytes++] = '\0';
            if (ALLOC_ALIGNUP(total_bytes) < ALLOC_ALIGNUP(ias_certs_len))
                INLINE_SYSCALL(munmap, 2, ALLOC_ALIGNUP(total_bytes),
                               ALLOC_ALIGNUP(ias_certs_len) - ALLOC_ALIGNUP(total_bytes));
            ias_certs_len = total_bytes;
        }

        start = next_start;
        end   = strchr(start, '\n');
    }

    if (!ias_sig) {
        SGX_DBG(DBG_E, "IAS returned invalid headers: no report signature\n");
        goto failed;
    }

    if (!ias_certs) {
        SGX_DBG(DBG_E, "IAS returned invalid headers: no certificate chain\n");
        goto failed;
    }

    attestation->ias_report     = https_output;
    attestation->ias_report_len = https_output_len;
    attestation->ias_sig        = ias_sig;
    attestation->ias_sig_len    = ias_sig_len;
    attestation->ias_certs      = ias_certs;
    attestation->ias_certs_len  = ias_certs_len;
    https_output = NULL; // Don't free the HTTPS output
    ret = 0;
done:
    if (https_header)
        INLINE_SYSCALL(munmap, 2, https_header, ALLOC_ALIGNUP(https_header_len));
    if (https_output)
        INLINE_SYSCALL(munmap, 2, https_output, ALLOC_ALIGNUP(https_output_len));
    if (pipefds[0] != -1) INLINE_SYSCALL(close, 1, pipefds[0]);
    if (pipefds[1] != -1) INLINE_SYSCALL(close, 1, pipefds[1]);
    if (header_fd != -1) {
        INLINE_SYSCALL(close,  1, header_fd);
        INLINE_SYSCALL(unlink, 1, https_header_path);
    }
    if (output_fd != -1) {
        INLINE_SYSCALL(close,  1, output_fd);
        INLINE_SYSCALL(unlink, 1, https_output_path);
    }
    return ret;
failed:
    ret = -PAL_ERROR_DENIED;
    goto done;
}

int retrieve_verified_quote(const sgx_spid_t* spid, bool linkable,
                            const sgx_arch_report_t* report, const sgx_quote_nonce_t* nonce,
                            sgx_attestation_t* attestation) {

    int ret = connect_aesm_service();
    if (ret < 0)
        return ret;

    Request req = REQUEST__INIT;
    Request__GetQuoteRequest getreq = REQUEST__GET_QUOTE_REQUEST__INIT;
    getreq.report.data   = (uint8_t*) report;
    getreq.report.len    = SGX_REPORT_ACTUAL_SIZE;
    getreq.quote_type    = linkable ? SGX_LINKABLE_SIGNATURE : SGX_UNLINKABLE_SIGNATURE;
    getreq.spid.data     = (uint8_t*) spid;
    getreq.spid.len      = sizeof(*spid);
    getreq.has_nonce     = true;
    getreq.nonce.data    = (uint8_t*) nonce;
    getreq.nonce.len     = sizeof(*nonce);
    getreq.buf_size      = SGX_QUOTE_MAX_SIZE;
    getreq.has_qe_report = true;
    getreq.qe_report     = true;
    req.getquotereq      = &getreq;

    Response* res = NULL;
    ret = request_aesm_service(&req, &res);
    if (ret < 0)
        return ret;

    if (!res->getquoteres) {
        SGX_DBG(DBG_E, "aesm_service returned wrong message\n");
        goto failed;
    }

    Response__GetQuoteResponse* r = res->getquoteres;
    if (r->errorcode != 0) {
        SGX_DBG(DBG_E, "aesm_service returned error: %d\n", r->errorcode);
        goto failed;
    }

    if (!r->has_quote     || r->quote.len < sizeof(sgx_quote_t) ||
        !r->has_qe_report || r->qe_report.len != SGX_REPORT_ACTUAL_SIZE) {
        SGX_DBG(DBG_E, "aesm_service returned invalid quote or report\n");
        goto failed;
    }

    sgx_quote_t* quote = (sgx_quote_t*) INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(r->quote.len),
                                                       PROT_READ|PROT_WRITE,
                                                       MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (IS_ERR_P(quote)) {
        SGX_DBG(DBG_E, "Failed to allocate memory for the quote\n");
        goto failed;
    }

    memcpy(quote, r->quote.data, r->quote.len);
    attestation->quote = quote;
    attestation->quote_len = r->quote.len;

    ret = contact_intel_attest_service(nonce, (sgx_quote_t *) quote, attestation);
    if (ret < 0) {
        INLINE_SYSCALL(munmap, 2, quote, ALLOC_ALIGNUP(r->quote.len));
        goto failed;
    }

    memcpy(&attestation->qe_report, r->qe_report.data, sizeof(sgx_arch_report_t));
    response__free_unpacked(res, NULL);
    return 0;

failed:
    response__free_unpacked(res, NULL);
    return -PAL_ERROR_DENIED;
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
