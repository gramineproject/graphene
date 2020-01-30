/* Copyright (C) 2019, Texas A&M University.

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <pal_linux.h>
#include <pal_rtld.h>
#include <pal_crypto.h>
#include <hex.h>

#include "sgx_internal.h"
#include "sgx_arch.h"
#include "sgx_enclave.h"
#include "sgx_attest.h"
#include "quote/aesm.pb-c.h"

#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/un.h>
#define __USE_XOPEN2K8
#include <stdlib.h>

/*
 * Connect to the AESM service to interact with the architectural enclave. Must reconnect
 * for each request to the AESM service.
 *
 * Some older versions of AESM service use a UNIX socket at "\0sgx_aesm_socket_base".
 * The latest AESM service binds the socket at "/var/run/aesmd/aesm.socket". This function
 * tries to connect to either of the paths to ensure connectivity.
 */
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

/*
 * A wrapper for both creating a connection to the AESM service and submitting a request
 * to the service. Upon success, the function returns a response from the AESM service
 * back to the caller.
 */
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

// Retrieve the sgx_target_info_t of quoting enclave (QE).
int init_quoting_enclave_targetinfo(sgx_target_info_t* qe_target_info) {

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

    if (r->targetinfo.len != sizeof(*qe_target_info)) {
        SGX_DBG(DBG_E, "aesm_service returned invalid target info\n");
        goto failed;
    }

    memcpy(qe_target_info, r->targetinfo.data, sizeof(*qe_target_info));
    ret = 0;
failed:
    response__free_unpacked(res, NULL);
    return ret;
}

/**
 * Contact Intel Attestation Service to retrieve the signed attestation report and related
 * meta-data.
 *
 * @param subkey SPID subscription key.
 * @param nonce Random nonce to verify response freshness.
 * @param quote Platform quote retrieved from AESMD.
 * @param ias_report Attestation report returned by IAS.
 * @param ias_report_len Length in bytes of #ias_report.
 * @param ias_https_header HTTPS header(s) returned by IAS.
 * @param ias_https_header_len Length in bytes of #ias_https_header.
 */
int contact_intel_attest_service(const char* subkey, const sgx_quote_nonce_t* nonce,
                                 const sgx_quote_t* quote, char** ias_report, size_t* ias_report_len,
                                 char** ias_https_header, size_t* ias_https_header_len) {

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
    char    https_header_path[] = "/tmp/gsgx-ias-header-XXXXXX";
    char    https_output_path[] = "/tmp/gsgx-ias-output-XXXXXX";
    char*   https_header = NULL;
    char*   https_output = NULL;
    ssize_t https_header_len = 0;
    ssize_t https_output_len = 0;
    int header_fd = -1;
    int output_fd = -1;
    int fds[2] = {-1, -1};

    header_fd = mkstemp(https_header_path);
    if (header_fd < 0)
        goto failed;

    output_fd = mkstemp(https_output_path);
    if (output_fd < 0)
        goto failed;

    ret = INLINE_SYSCALL(socketpair, 4, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &fds[0]);
    if (IS_ERR(ret))
        goto failed;

    // Write HTTPS request in XML format
    size_t https_request_len = quote_str_len + nonce_str_len + HTTPS_REQUEST_MAX_LENGTH;
    char*  https_request = __alloca(https_request_len);
    https_request_len = snprintf(https_request, https_request_len,
                                 "{\"isvEnclaveQuote\":\"%s\",\"nonce\":\"%s\"}",
                                 quote_str, nonce_str);

    ret = INLINE_SYSCALL(write, 3, fds[1], https_request, https_request_len);
    if (IS_ERR(ret))
        goto failed;
    INLINE_SYSCALL(close, 1, fds[1]);
    fds[1] = -1;

    char subscription_header[64];
    snprintf(subscription_header, 64, "Ocp-Apim-Subscription-Key: %s", subkey);

    // Start a HTTPS client (using CURL)
    const char* https_client_args[] = {
            "/usr/bin/curl", "-s", "--tlsv1.2", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", subscription_header,
            "--data", "@-", "-o", https_output_path, "-D", https_header_path,
            IAS_REPORT_URL, NULL,
        };

    int pid = ARCH_VFORK();
    if (IS_ERR(pid))
        goto failed;

    if (!pid) {
        INLINE_SYSCALL(dup2, 2, fds[0], 0);
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
    https_output = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGN_UP(https_output_len),
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
    https_header = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGN_UP(https_header_len),
                                         PROT_READ, MAP_PRIVATE|MAP_FILE, header_fd, 0);
    if (IS_ERR_P(https_header))
        goto failed;

    *ias_report           = https_output;
    *ias_report_len       = https_output_len;
    *ias_https_header     = https_header;
    *ias_https_header_len = https_header_len;

    https_header = NULL; // Don't free the HTTPS output
    https_output = NULL; // Don't free the HTTPS output

    ret = 0;
done:
    if (https_header)
        INLINE_SYSCALL(munmap, 2, https_header, ALLOC_ALIGN_UP(https_header_len));
    if (https_output)
        INLINE_SYSCALL(munmap, 2, https_output, ALLOC_ALIGN_UP(https_output_len));
    if (fds[0] != -1)
        INLINE_SYSCALL(close, 1, fds[0]);
    if (fds[1] != -1)
        INLINE_SYSCALL(close, 1, fds[1]);
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

/**
 * The function first contacts the AESM service to retrieve a quote of the platform and the report
 * of the quoting enclave. Then, the function submits the quote to IAS through an HTTPS client
 * (CURL) to exchange for a remote attestation report signed by an Intel-approved certificate
 * chain. The function returns the IAS response and associated meta-data (HTTP headers).
 *
 * @param spid        The client SPID registered with IAS.
 * @param subkey      SPID subscription key.
 * @param linkable    A boolean that represents whether the SPID is linkable.
 * @param report      The local report of the target enclave.
 * @param nonce       A 16-byte nonce randomly generated inside the enclave.
 */
int retrieve_verified_quote(const sgx_spid_t* spid, const char* subkey, bool linkable,
                            const sgx_report_t* report, const sgx_quote_nonce_t* nonce,
                            char** ias_report, size_t* ias_report_len, char** ias_header, size_t* ias_header_len) {

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

    sgx_quote_t* quote = (sgx_quote_t*) INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGN_UP(r->quote.len),
                                                       PROT_READ|PROT_WRITE,
                                                       MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (IS_ERR_P(quote)) {
        SGX_DBG(DBG_E, "Failed to allocate memory for the quote\n");
        goto failed;
    }

    memcpy(quote, r->quote.data, r->quote.len);

    ret = contact_intel_attest_service(subkey, nonce, (sgx_quote_t *) quote, ias_report,
                                       ias_report_len, ias_header, ias_header_len);
    INLINE_SYSCALL(munmap, 2, quote, ALLOC_ALIGN_UP(r->quote.len));
    if (ret < 0)
        goto failed;

    response__free_unpacked(res, NULL);
    return 0;

failed:
    response__free_unpacked(res, NULL);
    return -PAL_ERROR_DENIED;
}
