#include <pal_linux.h>
#include <pal_rtld.h>
#include <pal_crypto.h>
#include <hex.h>

#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "graphene-sgx.h"
#include "quote/aesm.pb-c.h"

#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/un.h>

#ifndef PF_UNIX
# define PF_UNIX 1
#endif

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

    int ret, sock = INLINE_SYSCALL(socket, 3, PF_UNIX, SOCK_STREAM, 0);
    if (IS_ERR(sock))
        return -ERRNO(sock);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void) strcpy_static(addr.sun_path, "\0sgx_aesm_socket_base", sizeof(addr.sun_path));

    ret = INLINE_SYSCALL(connect, 3, sock, &addr, sizeof(addr));
    if (!IS_ERR(ret))
        goto success;
    if (ERRNO(ret) != ECONNREFUSED)
        goto err;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void) strcpy_static(addr.sun_path, "/var/run/aesmd/aesm.socket", sizeof(addr.sun_path));

    ret = INLINE_SYSCALL(connect, 3, sock, &addr, sizeof(addr));
    if (IS_ERR(ret))
        goto err;

success:
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
        return -ERRNO(ret);

    ret = INLINE_SYSCALL(write, 3, aesm_socket, req_buf, req_len);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    uint32_t res_len;
    ret = INLINE_SYSCALL(read, 3, aesm_socket, &res_len, sizeof(res_len));
    if (IS_ERR(ret))
        return -ERRNO(ret);

    uint8_t* res_buf = __alloca(res_len);
    ret = INLINE_SYSCALL(read, 3, aesm_socket, res_buf, res_len);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    *res = response__unpack(NULL, res_len, res_buf);
    return *res == NULL ? -EINVAL : 0;
}

int init_quote(sgx_arch_targetinfo_t* aesm_targetinfo) {

    Request req = REQUEST__INIT;
    Request__InitQuoteRequest initreq = REQUEST__INIT_QUOTE_REQUEST__INIT;
    req.initquotereq = &initreq;

    Response* res = NULL;
    int ret = request_aesm_service(&req, &res);
    if (ret < 0)
        return ret;

    if (!res->initquoteres) {
        SGX_DBG(DBG_E, "aesm_service returns wrong message\n");
        goto failed;
    }

    Response__InitQuoteResponse* r = res->initquoteres;
    if (r->errorcode != 0) {
        SGX_DBG(DBG_E, "aesm_service returns error: %d\n", r->errorcode);
        goto failed;
    }

    assert(r->targetinfo.len == sizeof(*aesm_targetinfo));
    memcpy(aesm_targetinfo, r->targetinfo.data, sizeof(*aesm_targetinfo));
    response__free_unpacked(res, NULL);
    return 0;

failed:
    response__free_unpacked(res, NULL);
    return -EPERM;
}

#define IAS_TEST_REPORT_URL \
    "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v3/report"

int contact_intel_attest_service(const sgx_quote_nonce_t* nonce, const sgx_quote_t* quote) {

    int ret = 0;
    char* quote_str = lib_Base64Encode((uint8_t*)quote, sizeof(sgx_quote_t) + quote->sig_len, NULL);
    char* nonce_str = __bytes2hexstr((void *) nonce, sizeof(sgx_quote_nonce_t),
                      malloc(sizeof(sgx_quote_nonce_t) * 2 + 1), sizeof(sgx_quote_nonce_t) * 2 + 1);

    char body_path[URI_MAX], resp_path[URI_MAX], head_path[URI_MAX];
    const char* temp_dir = (const char *) current_enclave->pal_sec.temp_dir;
    char* head = NULL;
    char* resp = NULL;
    snprintf(body_path, URI_MAX, "@%sias-body",  temp_dir);
    snprintf(resp_path, URI_MAX, "%sias-resp",   temp_dir);
    snprintf(head_path, URI_MAX, "%sias-header", temp_dir);

    int body_file = INLINE_SYSCALL(open, 3, body_path + 1, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (IS_ERR(body_file))
        goto failed;

    const char* body_lines[5] = {
        "{\"isvEnclaveQuote\":\"",
        quote_str,
        "\",\"nonce\":\"",
        nonce_str,
        "\"}"
    };

    for (size_t i = 0; i < 5; i++)
        INLINE_SYSCALL(write, 3, body_file, body_lines[i], strlen(body_lines[i]));

    INLINE_SYSCALL(close, 1, body_file);

    if (!current_enclave->ra_cert ||
        !current_enclave->ra_pkey) {
        SGX_DBG(DBG_E, "Need both certificate and private key for contacting IAS\n");
        goto failed;
    }

    const char* https_client_args[] = {
            "/usr/bin/curl", "-s", "--tlsv1.2", "-X", "POST", "-H", "Accept: application/json",
            "--cert", current_enclave->ra_cert,
            "--key",  current_enclave->ra_pkey,
            "--data", body_path, "-o", resp_path, "-D", head_path,
            IAS_TEST_REPORT_URL, NULL,
        };

    ret = ARCH_VFORK();
    if (IS_ERR(ret))
        goto failed;

    if (!ret) {
        extern char** environ;
        INLINE_SYSCALL(execve, 3, https_client_args[0], https_client_args, environ);

        /* shouldn't get to here */
        SGX_DBG(DBG_E, "unexpected failure of new process\n");
        __asm__ volatile ("hlt");
        return 0;
    }

    int status;
    INLINE_SYSCALL(wait4, 4, ret, &status, 0, NULL);

    // Reading response
    int resp_file = INLINE_SYSCALL(open, 2, resp_path, O_RDONLY);
    if (IS_ERR(resp_file))
        goto failed;

    size_t resp_size = INLINE_SYSCALL(lseek, 3, resp_file, 0, SEEK_END);
    resp = malloc(resp_size + 1);
    INLINE_SYSCALL(lseek, 3, resp_file, 0, SEEK_SET);
    ret = INLINE_SYSCALL(read, 3, resp_file, resp, resp_size);
    if (IS_ERR(ret) || (size_t) ret < resp_size)
        goto failed;
    resp[resp_size] = '\0';

    // Reading headers
    int head_file = INLINE_SYSCALL(open, 2, head_path, O_RDONLY);
    if (IS_ERR(head_file))
        goto failed;

    size_t head_size = INLINE_SYSCALL(lseek, 3, head_file, 0, SEEK_END);
    head = malloc(head_size + 1);
    INLINE_SYSCALL(lseek, 3, head_file, 0, SEEK_SET);
    ret = INLINE_SYSCALL(read, 3, head_file, head, head_size);
    if (IS_ERR(ret) || (size_t) ret < head_size)
        goto failed;
    head[head_size] = '\0';

    size_t   ias_sig_len = 0;
    uint8_t* ias_sig     = NULL;
    char*    ias_cert    = NULL;
    char*    start       = head;
    char*    end         = strchr(head, '\n');
    while (end) {
        if (strpartcmp_static(start, "x-iasreport-signature: ")) {
            start += static_strlen("x-iasreport-signature: ");
            ias_sig = lib_Base64Decode(start, end - start, &ias_sig_len);
        } else if (strpartcmp_static(start, "x-iasreport-signing-certificate: ")) {
            start += static_strlen("x-iasreport-signing-certificate: ");
            size_t len = end - start;
            char* p = ias_cert = malloc(len + 1);
            for (size_t i = 0; i < len; i++) {
                if (start[i] == '%') {
                    int8_t hex1 = hex2dec(start[i + 1]), hex2 = hex2dec(start[i + 2]);
                    if (hex1 < 0 || hex2 < 0)
                        goto failed;
                    *(p++) = hex1 * 16 + hex2;
                    i += 2;
                } else {
                    *(p++) = start[i];
                }
            }
            *p = '\0';
        }

        start = end + 1;
        end   = strchr(start, '\n');
    }

    if (!ias_sig_len || !ias_sig || !ias_cert) {
        SGX_DBG(DBG_E, "IAS return invalid headers\n");
        goto failed;
    }

    SGX_DBG(DBG_S, "IAS response:   %s\n",  resp);
    SGX_DBG(DBG_S, "IAS signature:  %ld\n", ias_sig_len);
    SGX_DBG(DBG_S, "IAS cert:       %s\n",  ias_cert);

    ret = 0;
done:
    if (head) free(head);
    if (resp) free(resp);
    INLINE_SYSCALL(unlink, 1, body_path + 1);
    INLINE_SYSCALL(unlink, 1, resp_path);
    INLINE_SYSCALL(unlink, 1, head_path);
    free(quote_str);
    free(nonce_str);
    return ret;
failed:
    ret = -PAL_ERROR_DENIED;
    goto done;
}

enum {
    SGX_UNLINKABLE_SIGNATURE,
    SGX_LINKABLE_SIGNATURE
};

#define SGX_QUOTE_MAX_SIZE   (2048)

int get_quote(const sgx_spid_t* spid, bool linkable, const sgx_arch_report_t* report,
              const sgx_quote_nonce_t* nonce, sgx_arch_report_t* qe_report, sgx_quote_t* quote) {

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
        SGX_DBG(DBG_E, "aesm_service returns wrong message\n");
        goto failed;
    }

    Response__GetQuoteResponse* r = res->getquoteres;
    if (r->errorcode != 0) {
        SGX_DBG(DBG_E, "aesm_service returns error: %d\n", r->errorcode);
        goto failed;
    }

    if (!r->has_quote     || r->quote.len < sizeof(sgx_quote_t) ||
        !r->has_qe_report || r->qe_report.len != SGX_REPORT_ACTUAL_SIZE) {
        SGX_DBG(DBG_E, "aesm_service returns invalid quote or report\n");
        goto failed;
    }

    ret = contact_intel_attest_service(nonce, (sgx_quote_t *) r->quote.data);
    if (ret < 0)
        goto failed;

    memcpy(quote, r->quote.data, sizeof(sgx_quote_t));
    memcpy(qe_report, r->qe_report.data, sizeof(sgx_arch_report_t));
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

// Need this function because it's used by mbedtls_adaptor.c
size_t _DkRandomBitsRead (void * buffer, size_t size)
{
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}
