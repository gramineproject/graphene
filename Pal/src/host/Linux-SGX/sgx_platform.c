/* Copyright (C) 2019, University of North Carolina at Chapel Hill.

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
#include "graphene-sgx.h"
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

// Retrieve the targetinfo for the AESM enclave for generating the local attestation report.
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
 *
 * @subkey:      SPID subscription key.
 * @nonce:       Random nonce generated in the enclave.
 * @quote:       Platform quote retrieved from AESMD.
 * @attestation: Attestation data to be returned to the enclave.
 */
int contact_intel_attest_service(const char* subkey, const sgx_quote_nonce_t* nonce,
                                 const sgx_quote_t* quote, sgx_attestation_t* attestation) {

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

        if (strpartcmp_static(start, "X-IASReport-Signature: ")) {
            start += static_strlen("X-IASReport-Signature: ");

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
        } else if (strpartcmp_static(start, "X-IASReport-Signing-Certificate: ")) {
            start += static_strlen("X-IASReport-Signing-Certificate: ");

            // Decode IAS signature chain
            ias_certs_len = end - start;
            ias_certs = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGNUP(ias_certs_len),
                                              PROT_READ|PROT_WRITE,
                                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (IS_ERR_P(ias_certs)) {
                SGX_DBG(DBG_E, "Cannot allocate memory for IAS certificate chain\n");
                goto failed;
            }

            /*
             * The value of x-iasreport-signing-certificate is a certificate chain which
             * consists of multiple certificates represented in the PEM format. The value
             * is escaped using the % character. For example, a %20 in the certificate
             * needs to be replaced as the newline ("\n"). The following logic interatively
             * reads the character and coverts the escapted characters into the buffer.
             */
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

    // Now return the attestation data, including the IAS response, signature, and the
    // certificate chain back to the caller.
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

/*
 * This wrapper function performs the whole attestation procedure outside the enclave (except
 * retrieving the local remote attestation and verification). The function first contacts
 * the AESM service to retrieve a quote of the platform and the report of the quoting enclave.
 * Then, the function submits the quote to the IAS through a HTTPS client (CURL) to exchange
 * for a remote attestation report signed by a Intel-approved certificate chain. Finally, the
 * function returns the QE report, the quote, and the response from the IAS back to the enclave
 * for verification.
 *
 * @spid:        The client SPID registered with IAS.
 * @subkey:      SPID subscription key.
 * @linkable:    A boolean that represents whether the SPID is linkable.
 * @report:      The local report of the target enclave.
 * @nonce:       A 16-byte nonce randomly generated inside the enclave.
 * @attestation: A structure for storing the response from the AESM service and the IAS.
 */
int retrieve_verified_quote(const sgx_spid_t* spid, const char* subkey, bool linkable,
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

    ret = contact_intel_attest_service(subkey, nonce, (sgx_quote_t *) quote, attestation);
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
