/* Copyright (C) 2018-2020 Intel Labs
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

#include <stdint.h>
#include <mbedtls/ssl.h>

/* envvars for client (attester) */
#define SECRET_PROVISION_CONSTRUCTOR    "SECRET_PROVISION_CONSTRUCTOR"
#define SECRET_PROVISION_CA_CHAIN_PATH  "SECRET_PROVISION_CA_CHAIN_PATH"
#define SECRET_PROVISION_SERVERS        "SECRET_PROVISION_SERVERS"
#define SECRET_PROVISION_SECRET_STRING  "SECRET_PROVISION_SECRET_STRING"

/* envvars for server (verifier) */
#define SECRET_PROVISION_LISTENING_PORT "SECRET_PROVISION_LISTENING_PORT"

/* internal secret-provisioning protocol message format */
#define SECRET_PROVISION_REQUEST  "SECRET_PROVISION_RA_TLS_REQUEST_V1"
#define SECRET_PROVISION_REQUEST_LEN (sizeof(SECRET_PROVISION_REQUEST) - 1)

#define SECRET_PROVISION_RESPONSE "SECRET_PROVISION_RA_TLS_RESPONSE_V1:" // 8B secret size follows
#define SECRET_PROVISION_RESPONSE_LEN (sizeof(SECRET_PROVISION_RESPONSE) - 1)

#define DEFAULT_SERVERS "localhost:4433"

typedef int (*verify_measurements_cb_t)(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn);

typedef int (*secret_provision_cb_t)(void* ssl);

/*!
 * \brief Write arbitrary data in an established RA-TLS session.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start() or in the server-side callback secret_provision_cb_t().
 *
 * \param[in] ssl  Established RA-TLS session, obtained from secret_provision_start() or in
 *                 secret_provision_cb_t() callback.
 * \param[in] buf  Buffer with arbitrary data to write.
 * \param[in] len  Size of buffer.
 *
 * \return         0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_write(void* ssl, const uint8_t* buf, size_t len);

/*!
 * \brief Read arbitrary data in an established RA-TLS session.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start() or in the server-side callback secret_provision_cb_t().
 *
 * \param[in] ssl  Established RA-TLS session, obtained from secret_provision_start() or in
 *                 secret_provision_cb_t() callback.
 * \param[out] buf Buffer with arbitrary data to read.
 * \param[in] len  Size of buffer.
 *
 * \return         0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_read(void* ssl, uint8_t* buf, size_t len);

/*!
 * \brief Close an established RA-TLS session.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start() or in the server-side callback secret_provision_cb_t(). Typically,
 * application-specific protocol to provision secrets is implemented via secret_provision_read()
 * and secret_provision_write(), and this function is called to finish secret provisioning.
 *
 * \param[in] ssl  Established RA-TLS session.
 *
 * \return         0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_close(void* ssl);

/*!
 * \brief Get a provisioned secret.
 *
 * This function is relevant only for clients. Typically, the client would ask for secret
 * provisioning via secret_provision_start() which will obtain the secret from the server and
 * save it in enclave memory. After that, the client can call this function to retrieve the
 * secret from memory.
 *
 * \param[out] out_secret      Pointer to buffer with secret (allocated by the library).
 * \param[out] out_secret_len  Size of allocated buffer.
 *
 * \return                     0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_get(uint8_t** out_secret, size_t* out_secret_len);

/*!
 * \brief Destroy a provisioned secret.
 *
 * This function zeroes out the memory where provisioned secret is stored and frees it.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
void secret_provision_destroy(void);

/*!
 * \brief Establish an RA-TLS session and retrieve first secret (client-side).
 *
 * This function must be called before other functions. It establishes a secure RA-TLS session
 * with the first available server from the \a in_servers list and retrieves the first secret.
 * If \a out_ssl pointer is supplied by the user, the session is not closed and the user can
 * continue this secure session with the server via secret_provision_read(),
 * secret_provision_write(), and the final secret_provision_close(). The first secret can be
 * retrieved via secret_provision_get() and later destroyed via secret_provision_destroy().
 * Not thread-safe.
 *
 * \param[in] in_servers        List of servers (in format "server1:port1;server2:port2;..."). If
 *                              not specified, environment variable `SECRET_PROVISION_SERVERS` is
 *                              used. If the environment variable is also not specified, default
 *                              value is used.
 * \param[in] in_ca_chain_path  Path to the CA chain to verify the server. If not specified,
 *                              environment variable `SECRET_PROVISION_CA_CHAIN_PATH` is used. If
 *                              the environment variable is also not specified, function returns
 *                              with error code EINVAL.
 * \param[out] out_ssl          Pointer to an established RA-TLS session. If user supplies NULL,
 *                              then only the first secret is retrieved from the server and the
 *                              RA-TLS session is closed.
 *
 * \return                      0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_start(const char* in_servers, const char* in_ca_chain_path, void** out_ssl);

/*!
 * \brief Start a secret provisioning service (sever-side).
 *
 * This function starts a multi-threaded secret provisioning server. It listens to client
 * connections on \a port. For each new client, it spawns a new thread in which the RA-TLS
 * mutually-attested session is established. The server provides a normal X.509 certificate to the
 * client (initialized with \a cert_path and \a key_path). The server expects a self-signed RA-TLS
 * certificate from the client. During TLS handshake, the server invokes a user-supplied callback
 * m_cb() for user-specific verification of measurements in client's SGX quote (if user supplied
 * it). After successfuly establishing the RA-TLS session and sending the first secret \a secret,
 * the server invokes a user-supplied callback f_cb() for user-specific communication with the
 * client (if user supplied it). This function is thread-safe and requires pthread library.
 *
 * \param[in] secret      First secret (arbitrary binary blob) to send to client after
 *                        establishing RA-TLS session.
 * \param[in] secret_len  Size of first secret.
 * \param[in] port        Listening port of the server.
 * \param[in] cert_path   Path to X.509 certificate of the server.
 * \param[in] key_path    Path to private key of the server.
 * \param[in] m_cb        Callback for user-specific verification of measurements in client's SGX
 *                        quote. If user supplies NULL, then default logic of RA-TLS is invoked.
 * \param[in] f_cb        Callback for user-specific communication with the client, e.g., to send
 *                        more secrets. If user supplies NULL, then only the first secret is sent
 *                        to the client and the RA-TLS session is closed.
 *
 * \return                0 on success, specific error code (negative int) otherwise.
 */
__attribute__ ((visibility("default"))) __attribute__((weak))
int secret_provision_start_server(uint8_t* secret, size_t secret_len, const char* port,
                                  const char* cert_path, const char* key_path,
                                  verify_measurements_cb_t m_cb, secret_provision_cb_t f_cb);
