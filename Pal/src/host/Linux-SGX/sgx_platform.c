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

#include <asm/errno.h>
#include <linux/fs.h>
#include <linux/un.h>

#include "quote/aesm.pb-c.h"
#include "sgx_internal.h"

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
        SGX_DBG(DBG_E, "Quoting Enclave returned invalid target info\n");
        goto failed;
    }

    memcpy(qe_target_info, r->targetinfo.data, sizeof(*qe_target_info));
    ret = 0;
failed:
    response__free_unpacked(res, NULL);
    return ret;
}

int retrieve_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                   const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len) {
    int ret = connect_aesm_service();
    if (ret < 0)
        return ret;

    Request req = REQUEST__INIT;
    Request__GetQuoteRequest getreq = REQUEST__GET_QUOTE_REQUEST__INIT;
    getreq.report.data   = (uint8_t*)report;
    getreq.report.len    = SGX_REPORT_ACTUAL_SIZE;
    getreq.quote_type    = linkable ? SGX_LINKABLE_SIGNATURE : SGX_UNLINKABLE_SIGNATURE;
    getreq.spid.data     = (uint8_t*)spid;
    getreq.spid.len      = sizeof(*spid);
    getreq.has_nonce     = true;
    getreq.nonce.data    = (uint8_t*)nonce;
    getreq.nonce.len     = sizeof(*nonce);
    getreq.buf_size      = SGX_QUOTE_MAX_SIZE;
    getreq.has_qe_report = true;
    getreq.qe_report     = true;
    req.getquotereq      = &getreq;

    Response* res = NULL;
    ret = request_aesm_service(&req, &res);
    if (ret < 0)
        return ret;

    ret = -EPERM;

    if (!res->getquoteres) {
        SGX_DBG(DBG_E, "aesm_service returned wrong message\n");
        goto out;
    }

    Response__GetQuoteResponse* r = res->getquoteres;
    if (r->errorcode != 0) {
        SGX_DBG(DBG_E, "aesm_service returned error: %d\n", r->errorcode);
        goto out;
    }

    if (!r->has_quote     || r->quote.len < sizeof(sgx_quote_t) ||
        !r->has_qe_report || r->qe_report.len != SGX_REPORT_ACTUAL_SIZE) {
        SGX_DBG(DBG_E, "aesm_service returned invalid quote or report\n");
        goto out;
    }

    /* Intel SGX SDK implementation of the Quoting Enclave always sets `quote.len` to user-provided
     * `getreq.buf_size` (see above) instead of the actual size. We calculate the actual size here
     * by peeking into the quote and determining the size of the signature. */
    size_t actual_quote_size = sizeof(sgx_quote_t) + ((sgx_quote_t*)r->quote.data)->signature_len;
    if (actual_quote_size > SGX_QUOTE_MAX_SIZE) {
        SGX_DBG(DBG_E, "Size of the obtained SGX quote exceeds %d\n", SGX_QUOTE_MAX_SIZE);
        goto out;
    }

    char* mmapped = (char*)INLINE_SYSCALL(mmap, 6, NULL, ALLOC_ALIGN_UP(actual_quote_size),
                                          PROT_READ|PROT_WRITE,
                                          MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (IS_ERR_P(mmapped)) {
        SGX_DBG(DBG_E, "Failed to allocate memory for the quote\n");
        goto out;
    }

    memcpy(*quote, r->quote.data, actual_quote_size);

    *quote = mmapped;
    *quote_len = actual_quote_size;

    ret = 0;
out:
    response__free_unpacked(res, NULL);
    return ret;
}
