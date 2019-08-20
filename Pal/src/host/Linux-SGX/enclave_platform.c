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
#include <pal_linux_error.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>

#include "quote/generated-cacert.h"

/*
 * Graphene's simple remote attestation feature:
 *
 * This feature is for verifying the SGX hardware platforms for executing applications
 * in Graphene, to a remote trusted entity. The whole remote attestation process requires
 * interaction with the Intel Attestation Service (IAS) and Intel PSW enclave for
 * generating the remote and local quotes. Once the platform is fully verified, Graphene
 * will continue to initialize the library OS and the application; otherwise the execution
 * should terminate.
 *
 * Graphene's remote attestation process is meant to be transparent to the application;
 * that is, no change is required to the source code or binary of the application. The
 * remote attestation feature is enabled if "sgx.ra_client_spid" and "sgx.ra_client_key"
 * are specified in the manifest. To obtain the SPID and the subscription key, register in
 * the Intel API Portal: https://api.portal.trustedservices.intel.com/EPID-attestation.
 *
 * The remote attestation process contains four steps:
 *
 * (1) Initialization:
 *
 *    +-------------------+                    +-----------+                     +---------+
 *    | Intel PSW Enclave |  target info (PSW) | Untrusted |  target info (PSW)  | Enclave |
 *    |      (AESMD)      |------------------->|    PAL    |-------------------->|   PAL   |
 *    +-------------------+                    +-----------+                     +---------+
 *
 *    Before the enclave is created, Graphene contacts the AESMD to retrieve the target info
 *    of the Intel PSW enclave. The target info is used for generating local report later.
 *
 * (2) OCALL + Local attestation:
 *
 *    +---------+                        +-----------+                   +-------------------+
 *    | Enclave | OCALL(GET_ATTESTATION) | Untrusted | Report (PAL->PSW) | Intel PSW Enclave |
 *    |   PAL   |----------------------->|    PAL    |------------------>|      (AESMD)      |
 *    +---------+                        +-----------+                   +-------------------+
 *
 *    The enclave PAL uses ENCLU[EREPORT] to generate a local report for the PSW enclave to
 *    verify that the two enclaves are on the same platform. The enclave PAL then issues an
 *    OCALL(GET_ATTESTATION), alone with the report, the SPID, and the subscription key.
 *    The report is given to the PSW enclave to generate a local quote. The PSW enclave will
 *    verify the report, decide whether to trust the Graphene enclave, and then sign the
 *    local quote with a PSW-only attestation key.
 *
 * (3) Contact the IAS for platform report:
 *
 *    The local quote from the PSW enclave needs to be verified by the IAS. Different from the
 *    Intel SDK model, Graphene does not rely on another third party to contact the IAS.
 *    Graphene contact the IAS as part of its remote attestation process.
 *
 *    +-----------+               +--------------+                            +---------------+
 *    | Untrusted | fork + execve | HTTPS client |  HTTPS (quote, SPID, key)  | Intel Attest. |
 *    |    PAL    |-------------->|    (CURL)    |--------------------------->|    Service    |
 *    +-----------+               +--------------+                            +---------------+
 *
 *    Graphene now uses a commodity HTTPS client (CURL) to contact the IAS. This is not fully
 *    compliant to the TOS of the IAS, because the SPID and the key is not protected from
 *    the untrusted host. The verification of the SGX platform does not require secrecy of the
 *    SPID/key, because the SPID/key is only used by the IAS to identify the clients. Even if
 *    an attacker has obtained the SPID/key, the attacker cannot tamper the quote and the IAS
 *    attestation report.
 *
 * (4) Checking the IAS report:
 *
 *    +---------------+                   +-----------+ HTTPS resp, Certs,  +---------+
 *    | Intel Attest. | HTTPS resp, Certs | Untrusted | Report (PSW->PAL),  | Enclave |
 *    |    Service    |------------------>|    PAL    |-------------------->|   PAL   |
 *    +---------------+                   +-----------+                     +---------+
 *
 *    Finally, Graphene returns the HTTPS response and a certificate chain from the IAS
 *    back to the enclave PAL, alone with the local report from the PSW enclave. Graphene
 *    then verifies the attestation result based on the following criterion:
 *
 *    - The HTTPS response needs to be signed by the certificate chain, including the first
 *      certificate to generate the signature, and all the following certificates to sign
 *      the previous certificates.
 *    - The last certificate in the chain will be signed by a known IAS root CA, hard-coded
 *      in the enclave PAL.
 *    - The report from the PSW enclave needs to be verified. This will establish the mutual
 *      trust between the enclave PAL and the PSW enclave.
 *    - The HTTPS response from the IAS needs to contain the same quote generated from the
 *      PSW enclave, the same mrenclave, attributes, and 64-byte report data.
 *    - The HTTPS response needs to have an acceptable status, which is "OK" by default, or
 *      "GROUP_OUT_OF_DATE" if "sgx.ra_accept_group_out_of_date = 1" is in the manifest.
 *      If you obtain a status besides OK, please see the SECURITY ADVISORIES in README.md.
 */


/*
 * Perform the initial attestation procedure if "sgx.ra_client.spid" is specified in
 * the manifest file.
 */
int init_trusted_platform(void) {
    char spid_hex[sizeof(sgx_spid_t) * 2 + 1];
    ssize_t len = get_config(pal_state.root_config, "sgx.ra_client_spid", spid_hex,
                             sizeof(spid_hex));
    if (len <= 0) {
        SGX_DBG(DBG_E, "*** No client info specified in the manifest. "
                "Graphene will not perform remote attestation ***\n");
        return 0;
    }

    if (len != sizeof(sgx_spid_t) * 2) {
        SGX_DBG(DBG_E, "Malformed sgx.ra_client_spid value in the manifest: %s\n", spid_hex);
        return -PAL_ERROR_INVAL;
    }

    sgx_spid_t spid;
    for (ssize_t i = 0; i < len; i++) {
        int8_t val = hex2dec(spid_hex[i]);
        if (val < 0) {
            SGX_DBG(DBG_E, "Malformed sgx.ra_client_spid value in the manifest: %s\n", spid_hex);
            return -PAL_ERROR_INVAL;
        }
        spid[i/2] = spid[i/2] * 16 + (uint8_t)val;
    }

    char subkey[CONFIG_MAX];
    len = get_config(pal_state.root_config, "sgx.ra_client_key", subkey, CONFIG_MAX);
    if (len <= 0) {
        SGX_DBG(DBG_E, "No sgx.ra_client_key in the manifest\n");
        return -PAL_ERROR_INVAL;
    }

    char buf[2];
    len = get_config(pal_state.root_config, "sgx.ra_client_linkable", buf, sizeof(buf));
    bool linkable = (len == 1 && buf[0] == '1');

    len = get_config(pal_state.root_config, "sgx.ra_accept_group_out_of_date", buf, sizeof(buf));
    bool accept_group_out_of_date = (len == 1 && buf[0] == '1');

    sgx_quote_nonce_t nonce;
    int ret = _DkRandomBitsRead(&nonce, sizeof(nonce));
    if (ret < 0)
        return ret;

    char* status;
    char* timestamp;
    ret = sgx_verify_platform(&spid, subkey, &nonce, (sgx_arch_report_data_t*)&pal_enclave_state,
                              linkable, accept_group_out_of_date, NULL, &status, &timestamp);
    if (ret < 0)
        return ret;

    // If the attestation is successful, update the control block
    __pal_control.attestation_status = status;
    __pal_control.attestation_timestamp = timestamp;
    return ret;
}

/*
 * A simple function to parse a X509 certificate for only the certificate body, the signature,
 * and the public key.
 *
 * TODO: Currently no verification of the X509 certificate.
 *
 * @cert:     The certificate to parse (DER format).
 * @cert_len: The length of cert.
 * @body:     The certificate body (the signed part).
 * @body_len: The length of body.
 * @sig:      The certificate signature.
 * @sig_len:  The length of sig.
 * @pubkey:   The RSA public key from the certificate.
 */
static int parse_x509(uint8_t* cert, size_t cert_len, uint8_t** body, size_t* body_len,
                      uint8_t** sig, size_t* sig_len, LIB_RSA_KEY* pubkey) {
    uint8_t* ptr = cert;
    uint8_t* end = cert + cert_len;
    enum asn1_tag tag;
    bool is_cons;
    uint8_t* buf;
    size_t buf_len;
    int ret;

    // X509Certificate := SEQUENCE {
    //     Body CertificateBody,
    //     SignatureAlgorithm AlgorithmDescriptor,
    //     Signature BIT STRING }

    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
    if (ret < 0)
        return ret;
    if (tag != ASN1_SEQUENCE || !is_cons)
        return -PAL_ERROR_INVAL;

    uint8_t* cert_signed = ptr = buf;
    uint8_t* cert_body;
    uint8_t* cert_sig;
    size_t cert_body_len, cert_sig_len;
    end = buf + buf_len;

    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &cert_body, &cert_body_len);
    if (ret < 0)
        return ret;
    if (tag != ASN1_SEQUENCE || !is_cons)
        return -PAL_ERROR_INVAL;

    size_t cert_signed_len = ptr - cert_signed;

    // Skip SignatureAlgorithm
    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
    if (ret < 0)
        return ret;

    ret = lib_ASN1GetBitstring(&ptr, end, &cert_sig, &cert_sig_len);
    if (ret < 0)
        return ret;

    // CertficateBody := SEQUENCE {
    //     Version CONSTANT,
    //     SerialNumber INTEGER,
    //     Signature AlgorithmDiscriptor,
    //     Issuer Name,
    //     Validity ValidityTime,
    //     Subject Name,
    //     SubjectPublicKeyInfo PublicKeyInfo,
    //     (optional fields) }

    ptr = cert_body;
    end = cert_body + cert_body_len;

    // Skip Version, SerialNumber, Signature, Issuer, Validity, and Subject
    for (int i = 0; i < 6; i++) {
        ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
        if (ret < 0)
            return ret;
    }

    // Get SubjectPublicKeyInfo
    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
    if (ret < 0)
        return ret;
    if (tag != ASN1_SEQUENCE || !is_cons)
        return -PAL_ERROR_INVAL;

    // PublickKeyInfo := SEQUENCE {
    //     PublicKeyAlgorithm AlgorithmDescriptor,
    //     PublicKey BIT STRING }

    ptr = buf;
    end = buf + buf_len;

    // Skip PublicKeyAlgorithm
    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
    if (ret < 0)
        return ret;

    // Get PublicKey
    uint8_t* pkey_bits;
    size_t pkey_bits_len;

    ret = lib_ASN1GetBitstring(&ptr, end, &pkey_bits, &pkey_bits_len);
    if (ret < 0)
        return ret;

    // RSAPublicKey := SEQUENCE {
    //    Modulus Integer,
    //    PublicExponent Integer }

    ptr = pkey_bits;
    end = pkey_bits + pkey_bits_len;

    ret = lib_ASN1GetSerial(&ptr, end, &tag, &is_cons, &buf, &buf_len);
    if (ret < 0)
        return ret;

    uint8_t* mod;
    uint8_t* exp;
    size_t mod_len, exp_len;
    ptr = buf;
    end = buf + buf_len;

    ret = lib_ASN1GetLargeNumberLength(&ptr, end, &mod_len);
    if (ret < 0)
        return ret;

    mod = ptr;
    ptr += mod_len;

    ret = lib_ASN1GetLargeNumberLength(&ptr, end, &exp_len);
    if (ret < 0)
        return ret;

    exp = ptr;
    ptr += exp_len;

    *body = malloc(cert_signed_len);
    *body_len = cert_signed_len;
    memcpy(*body, cert_signed, cert_signed_len);

    *sig = malloc(cert_sig_len);
    *sig_len = cert_sig_len;
    memcpy(*sig, cert_sig, cert_sig_len);

    ret = lib_RSAInitKey(pubkey);
    if (ret < 0)
        return ret;

    ret = lib_RSAImportPublicKey(pubkey, exp, exp_len, mod, mod_len);
    if (ret < 0)
        return ret;

    return 0;
}

/*
 * Same as parse_x509(), but parse the certificate in PEM format.
 *
 * @cert:     The starting address for parsing the certificate.
 * @cert_end: Returns the end of certificate after parsing.
 * @body:     The certificate body (the signed part).
 * @body_len: The length of body.
 * @sig:      The certificate signature.
 * @sig_len:  The length of sig.
 * @pubkey:   The RSA public key from the certificate.
 */
static int parse_x509_pem(char* cert, char** cert_end, uint8_t** body, size_t* body_len,
                          uint8_t** sig, size_t* sig_len, LIB_RSA_KEY* pubkey) {

    int ret;
    char* start = strchr(cert, '-');
    if (!start) {
        // No more certificate
        *cert_end = NULL;
        return 0;
    }

    if (!strpartcmp_static(start, "-----BEGIN CERTIFICATE-----"))
        return -PAL_ERROR_INVAL;

    start += static_strlen("-----BEGIN CERTIFICATE-----");
    char* end = strchr(start, '-');

    if (!strpartcmp_static(end, "-----END CERTIFICATE-----"))
        return -PAL_ERROR_INVAL;

    size_t cert_der_len;
    ret = lib_Base64Decode(start, end - start, NULL, &cert_der_len);
    if (ret < 0)
        return ret;

    uint8_t* cert_der = __alloca(cert_der_len);
    ret = lib_Base64Decode(start, end - start, cert_der, &cert_der_len);
    if (ret < 0)
        return ret;

    ret = parse_x509(cert_der, cert_der_len, body, body_len, sig, sig_len, pubkey);
    if (ret < 0)
        return ret;

    *cert_end = end + static_strlen("-----END CERTIFICATE-----");
    return 0;
}

/*
 * Perform the remote attestation to verify the current SGX platform.
 *
 * The remote attestation procedure verifies two primary properties: (1) The current execution
 * runs in an SGX enclave; and (2) The enclave is created on a genuine, up-to-date Intel CPU.
 * This procedure requires interaction with the Intel PSW quoting enclave (AESMD) and the
 * Intel Attestation Service (IAS). The quoting enclave verifies a local attestation report
 * from the target enclave, and then generates a quoting enclave (QE) report and a platform
 * quote signed by the platform's attestation key. The IAS then verifies the platform quote and
 * issues a remote attestation report, signed by a certificate chain attached to the report.
 *
 * TODO: currently no verification of the correctness of the IAS certificate
 *
 * @spid:              The SPID registered for the Intel Attestation Service (IAS).
 * @subkey:            SPID subscription key.
 * @nonce:             A 16-byte nonce to be included in the quote.
 * @report_data:       A 64-byte bytestring to be included in the local report and the quote.
 * @linkable:          Specify whether the SPID is linkable.
 * @accept_group_out_of_date: Specify whether to accept GROUP_OUT_OF_DATE from IAS
 * @ret_attestation:   Returns the retrieved attestation data.
 * @ret_ias_status:    Returns a pointer to the attestation status (as a string) from the IAS.
 * @ret_ias_timestamp: Returns a pointer to the timestamp (as a string) from the IAS.
 *                     Timestamp format: %Y-%m-%dT%H:%M:%S.%f (Ex: 2019-08-01T12:30:00.123456)
 */
int sgx_verify_platform(sgx_spid_t* spid, const char* subkey, sgx_quote_nonce_t* nonce,
                        sgx_arch_report_data_t* report_data, bool linkable,
                        bool accept_group_out_of_date, sgx_attestation_t* ret_attestation,
                        char** ret_ias_status, char** ret_ias_timestamp) {

    SGX_DBG(DBG_S, "Request quote:\n");
    SGX_DBG(DBG_S, "  spid:  %s\n", ALLOCA_BYTES2HEXSTR(*spid));
    SGX_DBG(DBG_S, "  type:  %s\n", linkable ? "linkable" : "unlinkable");
    SGX_DBG(DBG_S, "  nonce: %s\n", ALLOCA_BYTES2HEXSTR(*nonce));

    sgx_arch_report_t report __sgx_mem_aligned;
    sgx_arch_targetinfo_t targetinfo __sgx_mem_aligned = pal_sec.aesm_targetinfo;

    int ret = sgx_report(&targetinfo, report_data, &report);
    if (ret) {
        SGX_DBG(DBG_E, "Failed to get report for attestation\n");
        return -PAL_ERROR_DENIED;
    }

    sgx_attestation_t attestation;
    ret = ocall_get_attestation(spid, subkey, linkable, &report, nonce, &attestation);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get attestation\n");
        return ret;
    }

    // First, verify the report from the quoting enclave
    ret = sgx_verify_report(&attestation.qe_report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to verify QE report, ret = %d\n", ret);
        goto failed;
    }

    // Verify the IAS response against the certificate chain
    uint8_t* data_to_verify = (uint8_t*)attestation.ias_report;
    uint8_t* data_sig       = attestation.ias_sig;
    size_t   data_len       = attestation.ias_report_len;
    size_t   data_sig_len   = attestation.ias_sig_len;

    // Attach the IAS signing chain with the hard-coded CA certificate
    const char* ca_cert = IAS_CA_CERT;
    size_t len1 = strlen(attestation.ias_certs);
    size_t len2 = static_strlen(IAS_CA_CERT);
    char* certs = malloc(len1 + len2 + 1);
    memcpy(certs, attestation.ias_certs, len1);
    memcpy(certs + len1, ca_cert, len2);
    certs[len1 + len2] = 0;
    free(attestation.ias_certs);
    attestation.ias_certs = certs;
    attestation.ias_certs_len = len1 + len2 + 1;

    // There can be multiple certificates in the chain. We need to use the public key from
    // the *first* certificate to verify the IAS response. For each certificate except
    // the last one, we need to use the public key from the *next* certificate to verify
    // the certificate body. The last certificate will be verified by the CA certificate
    // (hard-coded in the binary)

    for (char* cert_start = attestation.ias_certs;
         cert_start < attestation.ias_certs + attestation.ias_certs_len && *cert_start; ) {

        // Generate the message digest first (without RSA)
        LIB_SHA256_CONTEXT ctx;
        uint8_t hash[32];

        if ((ret = lib_SHA256Init(&ctx)) < 0)
            goto failed;

        if ((ret = lib_SHA256Update(&ctx, data_to_verify, data_len)) < 0)
            goto failed;

        if ((ret = lib_SHA256Final(&ctx, hash)) < 0)
            goto failed;

        // Use the public key to verify the last signature
        uint8_t*    cert_body;
        uint8_t*    cert_sig;
        size_t      cert_body_len;
        size_t      cert_sig_len;
        LIB_RSA_KEY cert_key;

        ret = parse_x509_pem(cert_start, &cert_start, &cert_body, &cert_body_len, &cert_sig,
                             &cert_sig_len, &cert_key);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to parse IAS certificate, rv = %d\n", ret);
            goto failed;
        }

        ret = lib_RSAVerifySHA256(&cert_key, hash, sizeof(hash), data_sig, data_sig_len);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to verify the report against the IAS certificates,"
                    " rv = %d\n", ret);
            lib_RSAFreeKey(&cert_key);
            goto failed;
        }

        lib_RSAFreeKey(&cert_key);

        data_to_verify = cert_body;
        data_sig       = cert_sig;
        data_len       = cert_body_len;
        data_sig_len   = cert_sig_len;
    }

    // Parse the IAS report in JSON format
    char* ias_status    = NULL;
    char* ias_timestamp = NULL;
    sgx_quote_nonce_t* ias_nonce = NULL;
    sgx_quote_t*       ias_quote = NULL;
    char* start = attestation.ias_report;
    if (start[0] == '{') start++;
    char* end = strchr(start, ',');
    while (end) {
        char* next_start = end + 1;

        // Retrieve the key and value separated by the colon (:)
        char* delim = strchr(start, ':');
        if (!delim)
            break;
        char*  key  = start;
        char*  val  = delim + 1;
        size_t klen = delim - start;
        size_t vlen = end - val;

        // Remove quotation marks (") around the key and value if there are any
        if (key[0] == '"') { key++; klen--; }
        if (key[klen - 1] == '"') klen--;
        if (val[0] == '"') { val++; vlen--; }
        if (val[vlen - 1] == '"') vlen--;

        // Scan the fields in the IAS report.
        if (!memcmp(key, "isvEnclaveQuoteStatus", klen)) {
            // Parse "isvEnclaveQuoteStatus":"OK"|"GROUP_OUT_OF_DATE"|...
            ias_status = __alloca(vlen + 1);
            memcpy(ias_status, val, vlen);
            ias_status[vlen] = 0;
        } else if (!memcmp(key, "nonce", klen)) {
            // Parse "nonce":"{Hex representation of the initial nonce}"
            if (vlen != sizeof(sgx_quote_nonce_t) * 2) {
                SGX_DBG(DBG_E, "Malformed nonce in the IAS report\n");
                goto failed;
            }

            ias_nonce = __alloca(sizeof(sgx_quote_nonce_t));
            for (size_t i = 0; i < sizeof(sgx_quote_nonce_t); i++) {
                int8_t hi = hex2dec(val[i * 2]);
                int8_t lo = hex2dec(val[i * 2 + 1]);
                if (hi < 0 || lo < 0) {
                    SGX_DBG(DBG_E, "Malformed nonce in the IAS report\n");
                    goto failed;
                }
                ((uint8_t*)ias_nonce)[i] = (uint8_t)hi * 16 + (uint8_t)lo;
            }
        } else if (!memcmp(key, "timestamp", klen)) {
            // Parse "timestamp":"{IAS timestamp (format: %Y-%m-%dT%H:%M:%S.%f)}"
            ias_timestamp = __alloca(vlen + 1);
            memcpy(ias_timestamp, val, vlen);
            ias_timestamp[vlen] = 0;
        } else if (!memcmp(key, "isvEnclaveQuoteBody", klen)) {
            // Parse "isvEnclaveQuoteBody":"{Quote body (in Base64 format)}"
            size_t ias_quote_len;
            ret = lib_Base64Decode(val, vlen, NULL, &ias_quote_len);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Malformed quote in the IAS report\n");
                goto failed;
            }

            ias_quote = __alloca(ias_quote_len);
            ret = lib_Base64Decode(val, vlen, (uint8_t*)ias_quote, &ias_quote_len);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Malformed quote in the IAS report\n");
                goto failed;
            }
        }

        start = next_start;
        end = strchr(start, ',') ? : strchr(start, '}');
    }

    if (!ias_status || !ias_nonce || !ias_timestamp || !ias_quote) {
        SGX_DBG(DBG_E, "Missing important field(s) in the IAS report\n");
        goto failed;
    }

    SGX_DBG(DBG_S, "Quote:\n");
    SGX_DBG(DBG_S, "  version:    %04x\n",  ias_quote->body.version);
    SGX_DBG(DBG_S, "  sigtype:    %04x\n",  ias_quote->body.sigtype);
    SGX_DBG(DBG_S, "  gid:        %08x\n",  ias_quote->body.gid);
    SGX_DBG(DBG_S, "  isvsvn qe:  %08x\n",  ias_quote->body.isvsvn_qe);
    SGX_DBG(DBG_S, "  isvsvn pce: %08x\n",  ias_quote->body.isvsvn_pce);

    SGX_DBG(DBG_S, "IAS report: %s\n", attestation.ias_report);
    SGX_DBG(DBG_S, "  status:    %s\n", ias_status);
    SGX_DBG(DBG_S, "  timestamp: %s\n", ias_timestamp);

    // Only accept status to be "OK" or "GROUP_OUT_OF_DATE" (if accept_out_of_date is true)
    if (!strcmp_static(ias_status, "OK") &&
        (!accept_group_out_of_date || !strcmp_static(ias_status, "GROUP_OUT_OF_DATE"))) {
        SGX_DBG(DBG_E, "IAS returned invalid status: %s\n", ias_status);
        goto failed;
    }

    // Check if the nonce matches the IAS report
    if (memcmp(ias_nonce, nonce, sizeof(sgx_quote_nonce_t))) {
        SGX_DBG(DBG_E, "IAS returned the wrong nonce\n");
        goto failed;
    }

    // Check if the quote matches the IAS report
    if (memcmp(&ias_quote->body, &attestation.quote->body, sizeof(sgx_quote_body_t)) ||
        memcmp(&ias_quote->report_body, &report.body, sizeof(sgx_arch_report_body_t))) {
        SGX_DBG(DBG_E, "IAS returned the wrong quote\n");
        goto failed;
    }

    // Check if the quote has the right enclave report
    if (memcmp(&attestation.quote->report_body, &report.body, sizeof(sgx_arch_report_body_t))) {
        SGX_DBG(DBG_E, "The returned quote contains the wrong enclave report\n");
        goto failed;
    }

    // Succeeded!!!
    if (ret_ias_status) {
        size_t len = strlen(ias_status) + 1;
        *ret_ias_status = malloc(len);
        memcpy(*ret_ias_status, ias_status, len);
    }

    if (ret_ias_timestamp) {
        size_t len = strlen(ias_timestamp) + 1;
        *ret_ias_timestamp = malloc(len);
        memcpy(*ret_ias_timestamp, ias_timestamp, len);
    }

    if (ret_attestation) {
        memcpy(ret_attestation, &attestation, sizeof(sgx_attestation_t));
        return 0;
    }
    ret = 0;
free_attestation:
    if (attestation.quote)      free(attestation.quote);
    if (attestation.ias_report) free(attestation.ias_report);
    if (attestation.ias_sig)    free(attestation.ias_sig);
    if (attestation.ias_certs)  free(attestation.ias_certs);
    return ret;

failed:
    ret = -PAL_ERROR_DENIED;
    goto free_attestation;
}
