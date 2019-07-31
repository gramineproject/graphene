#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>
#include <list.h>
#include <stdbool.h>

#include "enclave_pages.h"

struct pal_enclave_state pal_enclave_state;

void * enclave_base, * enclave_top;

struct pal_enclave_config pal_enclave_config;

static int register_trusted_file (const char * uri, const char * checksum_str);

bool sgx_is_completely_within_enclave (const void * addr, uint64_t size)
{
    if (((uint64_t) addr) > (UINT64_MAX - size)) {
        return false;
    }

    return enclave_base <= addr && addr + size <= enclave_top;
}

bool sgx_is_completely_outside_enclave(const void* addr, uint64_t size) {
    if (((uint64_t) addr) > (UINT64_MAX - size)) {
        return false;
    }

    return enclave_base >= addr + size || enclave_top <= addr;
}

void* sgx_alloc_on_ustack(uint64_t size) {
    void* ustack = GET_ENCLAVE_TLS(ustack) - size;
    if (!sgx_is_completely_outside_enclave(ustack, size)) {
        return NULL;
    }
    SET_ENCLAVE_TLS(ustack, ustack);
    return ustack;
}

void* sgx_copy_to_ustack(const void* ptr, uint64_t size) {
    if (!sgx_is_completely_within_enclave(ptr, size)) {
        return NULL;
    }
    void* uptr = sgx_alloc_on_ustack(size);
    if (uptr) {
        memcpy(uptr, ptr, size);
    }
    return uptr;
}

void sgx_reset_ustack(void) {
    SET_ENCLAVE_TLS(ustack, GET_ENCLAVE_TLS(ustack_top));
}

/* NOTE: Value from possibly untrusted uptr must be copied inside
 * CPU register or enclave stack (to prevent TOCTOU). Function call
 * achieves this. Attribute ensures no inline optimization. */
__attribute__((noinline))
bool sgx_copy_ptr_to_enclave(void** ptr, void* uptr, uint64_t size) {
    assert(ptr);
    if (!sgx_is_completely_outside_enclave(uptr, size)) {
        *ptr = NULL;
        return false;
    }
    *ptr = uptr;
    return true;
}

/* NOTE: Value from possibly untrusted uptr and usize must be copied
 * inside CPU registers or enclave stack (to prevent TOCTOU). Function
 * call achieves this. Attribute ensures no inline optimization. */
__attribute__((noinline))
uint64_t sgx_copy_to_enclave(const void* ptr, uint64_t maxsize, const void* uptr, uint64_t usize) {
    if (usize > maxsize ||
        !sgx_is_completely_outside_enclave(uptr, usize) ||
        !sgx_is_completely_within_enclave(ptr, usize)) {
        return 0;
    }
    memcpy((void*) ptr, uptr, usize);
    return usize;
}

static void print_report(sgx_arch_report_t* r) {
    SGX_DBG(DBG_S, "  cpusvn:     %08lx %08lx\n", r->body.cpusvn[0], r->body.cpusvn[1]);
    SGX_DBG(DBG_S, "  mrenclave:  %s\n",        ALLOCA_BYTES2HEXSTR(r->body.mrenclave));
    SGX_DBG(DBG_S, "  mrsigner:   %s\n",        ALLOCA_BYTES2HEXSTR(r->body.mrsigner));
    SGX_DBG(DBG_S, "  attr.flags: %016lx\n",    r->body.attributes.flags);
    SGX_DBG(DBG_S, "  attr.xfrm:  %016lx\n",    r->body.attributes.xfrm);
    SGX_DBG(DBG_S, "  isvprodid:  %02x\n",      r->body.isvprodid);
    SGX_DBG(DBG_S, "  isvsvn:     %02x\n",      r->body.isvsvn);
    SGX_DBG(DBG_S, "  reportdata: %s\n",        ALLOCA_BYTES2HEXSTR(r->body.report_data));
    SGX_DBG(DBG_S, "  keyid:      %s\n",        ALLOCA_BYTES2HEXSTR(r->keyid));
    SGX_DBG(DBG_S, "  mac:        %s\n",        ALLOCA_BYTES2HEXSTR(r->mac));
}

int sgx_get_report (sgx_arch_hash_t * mrenclave,
                    sgx_arch_attributes_t * attributes,
                    void * enclave_data,
                    sgx_arch_report_t * report)
{
    sgx_arch_targetinfo_t targetinfo;

    memset(&targetinfo, 0, sizeof(sgx_arch_targetinfo_t));
    memcpy(targetinfo.mrenclave, mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&targetinfo.attributes, attributes, sizeof(sgx_arch_attributes_t));

    struct pal_enclave_state state;
    memcpy(&state, &pal_enclave_state, sizeof(struct pal_enclave_state));
    memcpy(&state.data, enclave_data, PAL_ATTESTATION_DATA_SIZE);

    int ret = sgx_report(&targetinfo, &state, report);
    if (ret)
        return -PAL_ERROR_DENIED;

    SGX_DBG(DBG_S, "Generated report:\n");
    print_report(report);
    return 0;
}

static sgx_arch_key128_t enclave_key;

int sgx_verify_report (sgx_arch_report_t * report)
{
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = REPORT_KEY;
    memcpy(keyrequest.keyid, report->keyid, sizeof(keyrequest.keyid));

    sgx_arch_key128_t report_key;
    int ret = sgx_getkey(&keyrequest, &report_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get report key for verification: %s\n", ALLOCA_BYTES2HEXSTR(report_key));

    sgx_arch_mac_t check_mac;
    memset(&check_mac, 0, sizeof(sgx_arch_mac_t));

    lib_AESCMAC((uint8_t*)&report_key, sizeof(report_key),
                (uint8_t*)report, offsetof(sgx_arch_report_t, keyid),
                (uint8_t*)&check_mac, sizeof(sgx_arch_mac_t));

    memset(&report_key, 0, sizeof(sgx_arch_key128_t));

    SGX_DBG(DBG_S, "Verify report:\n");
    SGX_DBG(DBG_S, "    expected:         %s\n", ALLOCA_BYTES2HEXSTR(report->mac));
    SGX_DBG(DBG_S, "    mac:              %s\n", ALLOCA_BYTES2HEXSTR(check_mac));

    if (memcmp(&check_mac, &report->mac, sizeof(check_mac))) {
        SGX_DBG(DBG_S, "Local attestation verification failed\n");
        return -PAL_ERROR_DENIED;
    }

    return 0;
}

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

    char buf[2];
    len = get_config(pal_state.root_config, "sgx.ra_client_linkable", buf, sizeof(buf));
    bool linkable = (len == 1 && buf[0] == '1');

    sgx_quote_nonce_t nonce;
    int ret = _DkRandomBitsRead(&nonce, sizeof(nonce));
    if (ret < 0)
        return ret;

    return sgx_verify_platform(&spid, &nonce, (sgx_arch_report_data_t*)&pal_enclave_state,
                               linkable);
}

/*
 * A simple function to parse a X509 certificate for only the certificate body, the signature,
 * and the public key.
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
    //     Velidity ValidityTime,
    //     Subject Name,
    //     SubjectPublicKeyInfo PublicKeyInfo,
    //     (optional fields) }

    ptr = cert_body;
    end = cert_body + cert_body_len;

    // Skip Version, SerialNumber, Signature, Issuer, Validty, and Subject
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

int sgx_verify_platform(sgx_spid_t* spid, sgx_quote_nonce_t* nonce,
                        sgx_arch_report_data_t* report_data, bool linkable) {

    SGX_DBG(DBG_S, "Request quote:\n");
    SGX_DBG(DBG_S, "  spid:  %s\n", ALLOCA_BYTES2HEXSTR(*spid));
    SGX_DBG(DBG_S, "  type:  %s\n", linkable ? "linkable" : "unlinkable");
    SGX_DBG(DBG_S, "  nonce: %s\n", ALLOCA_BYTES2HEXSTR(*nonce));

    sgx_arch_report_t report;
    int ret = sgx_report(&pal_sec.aesm_targetinfo, report_data, &report);
    if (ret) {
        SGX_DBG(DBG_E, "Failed to get report for attestation\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Local report:\n");
    print_report(&report);

    sgx_attestation_t attestation;
    ret = ocall_get_attestation(spid, linkable, &report, nonce, &attestation);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get attestation\n");
        return ret;
    }

    // First, verify the report from the quoting enclave
    SGX_DBG(DBG_S, "QE report:\n");
    print_report(&attestation.qe_report);

    ret = sgx_verify_report(&attestation.qe_report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to QE verify report, ret = %d\n", ret);
        goto free_attestation;
    }

    // Verify the IAS response against the certificate chain
    uint8_t* data_to_verify = (uint8_t*)attestation.ias_report;
    uint8_t* data_sig       = attestation.ias_sig;
    size_t   data_len       = attestation.ias_report_len;
    size_t   data_sig_len   = attestation.ias_sig_len;

    for (char* cert_start = attestation.ias_certs;
         cert_start < attestation.ias_certs + attestation.ias_certs_len && *cert_start; ) {

        // Generate the message digest first (without RSA)
        LIB_SHA256_CONTEXT ctx;
        uint8_t hash[32];

        if ((ret = lib_SHA256Init(&ctx)) < 0)
            goto free_attestation;

        if ((ret = lib_SHA256Update(&ctx, data_to_verify, data_len)) < 0)
            goto free_attestation;

        if ((ret = lib_SHA256Final(&ctx, hash)) < 0)
            goto free_attestation;

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
            goto free_attestation;
        }

        ret = lib_RSAVerifySHA256(&cert_key, hash, sizeof(hash), data_sig, data_sig_len);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to verify the report against the IAS certificates,"
                    " rv = %d\n", ret);
            lib_RSAFreeKey(&cert_key);
            goto free_attestation;
        }

        lib_RSAFreeKey(&cert_key);

        data_to_verify = cert_body;
        data_sig       = cert_sig;
        data_len       = cert_body_len;
        data_sig_len   = cert_sig_len;
    }

    // Parse the IAS report in JSON format
    char* ias_status    = NULL;
    char* ias_nonce_str = NULL;
    char* ias_timestamp = NULL;
    char* ias_quote_str = NULL;
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
        key[klen] = 0;
        val[vlen] = 0;

        // Scan the fields in the IAS report
        if (strcmp_static(key, "isvEnclaveQuoteStatus")) {
            ias_status = val;
        } else if (strcmp_static(key, "nonce")) {
            ias_nonce_str = val;
        } else if (strcmp_static(key, "timestamp")) {
            ias_timestamp = val;
        } else if (strcmp_static(key, "isvEnclaveQuoteBody")) {
            ias_quote_str = val;
        }

        start = next_start;
        end = strchr(start, ',') ? : strchr(start, '}');
    }

    if (!ias_status || !ias_nonce_str || !ias_timestamp || !ias_quote_str) {
        SGX_DBG(DBG_E, "Missing important field(s) in the IAS report\n");
        goto free_attestation;
    }

    SGX_DBG(DBG_S, "IAS report:\n");
    SGX_DBG(DBG_S, "  status:    %s\n", ias_status);
    SGX_DBG(DBG_S, "  nonce:     %s\n", ias_nonce_str);
    SGX_DBG(DBG_S, "  timestamp: %s\n", ias_timestamp);
    SGX_DBG(DBG_S, "  quote:     %s\n", ias_quote_str);

    // For now, we only accept status to be "OK" or "GROUP_OUT_OF_DATE"
    if (!strcmp_static(ias_status, "OK") &&
        !strcmp_static(ias_status, "GROUP_OUT_OF_DATE")) {
        SGX_DBG(DBG_E, "IAS returned invalid status: %s\n", ias_status);
        goto free_attestation;
    }

    // Check if the nonce matches the IAS report
    size_t nonce_str_len = sizeof(sgx_quote_nonce_t) * 2 + 1;
    char* nonce_str = __alloca(nonce_str_len);
    __bytes2hexstr((void *)nonce, sizeof(sgx_quote_nonce_t), nonce_str, nonce_str_len);

    if (memcmp(ias_nonce_str, nonce_str, nonce_str_len)) {
        SGX_DBG(DBG_E, "IAS returned the wrong nonce: %s\n", ias_nonce_str);
        goto free_attestation;
    }

    // Check if the quote matches the IAS report
    size_t ias_quote_str_len = strlen(ias_quote_str);
    size_t ias_quote_len;
    ret = lib_Base64Decode(ias_quote_str, ias_quote_str_len, NULL, &ias_quote_len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Malformed quote in the IAS report\n");
        goto free_attestation;
    }

    sgx_quote_t* ias_quote = __alloca(ias_quote_len);
    ret = lib_Base64Decode(ias_quote_str, ias_quote_str_len, (uint8_t*)ias_quote, &ias_quote_len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Malformed quote in the IAS report\n");
        goto free_attestation;
    }

    if (memcmp(&ias_quote->body, &attestation.quote->body, sizeof(sgx_quote_body_t)) ||
        memcmp(&ias_quote->report_body, &report.body, sizeof(sgx_arch_report_body_t))) {
        SGX_DBG(DBG_E, "IAS returned the wrong quote\n");
        goto free_attestation;
    }

    // Check if the quote has the right enclave report
    if (memcmp(&attestation.quote->report_body, &report.body, sizeof(sgx_arch_report_body_t))) {
        SGX_DBG(DBG_E, "The returned quote contains the wrong enclave report\n");
        goto free_attestation;
    }

    return 0;

free_attestation:
    if (attestation.quote)      free(attestation.quote);
    if (attestation.ias_report) free(attestation.ias_report);
    if (attestation.ias_sig)    free(attestation.ias_sig);
    if (attestation.ias_certs)  free(attestation.ias_certs);
    return -PAL_ERROR_DENIED;
}

int init_enclave_key (void)
{
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = SEAL_KEY;

    int ret = sgx_getkey(&keyrequest, &enclave_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get sealing key: %s\n", ALLOCA_BYTES2HEXSTR(enclave_key));
    return 0;
}

/*
 * The file integrity check is designed as follow:
 *
 * For each file that requires authentication (specified in the manifest
 * as "sgx.trusted_files.xxx"), a SHA256 checksum is generated and stored
 * in the manifest, signed and verified as part of the enclave's crypto
 * measurement. When user requests for opening the file, Graphene loads
 * the whole file, generate the SHA256 checksum, and check with the known
 * checksums listed in the manifest. If the checksum does not match, and
 * neither does the file is allowed for unauthenticated access, the file
 * access will be rejected.
 *
 * During the generation of the SHA256 checksum, a 128-bit hash is also
 * generated for each chunk in the file. The per-chunk hashes are used
 * for partial verification in future reads, to avoid re-verifying the
 * whole file again or the need of caching file contents. The per-chunk
 * hashes are stored as "stubs" for each file. For a performance reason,
 * each per-chunk hash is a 128-bit AES-CMAC hash value, using a secret
 * key generated at the beginning of the enclave.
 */

DEFINE_LIST(trusted_file);
struct trusted_file {
    LIST_TYPE(trusted_file) list;
    int64_t index;
    uint64_t size;
    int uri_len;
    char uri[URI_MAX];
    sgx_checksum_t checksum;
    sgx_stub_t * stubs;
};

DEFINE_LISTP(trusted_file);
static LISTP_TYPE(trusted_file) trusted_file_list = LISTP_INIT;
static struct spinlock trusted_file_lock = LOCK_INIT;
static int trusted_file_indexes = 0;
static bool allow_file_creation = 0;


/*
 * 'load_trusted_file' checks if the file to be opened is trusted
 * or allowed for unauthenticated access, according to the manifest.
 *
 * file:     file handle to be opened
 * stubptr:  buffer for catching matched file stub.
 * sizeptr:  size pointer
 * create:   this file is newly created or not
 *
 * return:  0 succeed
 */
int load_trusted_file (PAL_HANDLE file, sgx_stub_t ** stubptr,
                       uint64_t * sizeptr, int create)
{
    struct trusted_file * tf = NULL, * tmp;
    char uri[URI_MAX];
    char normpath[URI_MAX];
    int ret, fd = file->file.fd, uri_len, len;

    if (!(HANDLE_HDR(file)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    uri_len = _DkStreamGetName(file, uri, URI_MAX);
    if (uri_len < 0)
        return uri_len;

    /* Allow to create the file when allow_file_creation is turned on;
       The created file is added to allowed_file list for later access */
    if (create && allow_file_creation) {
       register_trusted_file(uri, NULL);
       *sizeptr = 0;
       return 0;
    }

    /* Normalize the uri */
    if (!strpartcmp_static(uri, "file:")) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);;
        return -PAL_ERROR_INVAL;
    }
    normpath [0] = 'f';
    normpath [1] = 'i';
    normpath [2] = 'l';
    normpath [3] = 'e';
    normpath [4] = ':';
    len = get_norm_path(uri + 5, normpath + 5, 0, URI_MAX);
    uri_len = len + 5;

    _DkSpinLock(&trusted_file_lock);

    LISTP_FOR_EACH_ENTRY(tmp, &trusted_file_list, list) {
        if (tmp->stubs) {
            /* trusted files: must be exactly the same URI */
            if (tmp->uri_len == uri_len && !memcmp(tmp->uri, normpath, uri_len + 1)) {
                tf = tmp;
                break;
            }
        } else {
            /* allowed files: must be a subfolder or file */
            if (tmp->uri_len <= uri_len &&
                !memcmp(tmp->uri, normpath, tmp->uri_len) &&
                (!normpath[tmp->uri_len] || normpath[tmp->uri_len] == '/')) {
                tf = tmp;
                break;
            }
        }
    }

    _DkSpinUnlock(&trusted_file_lock);

    if (!tf)
        return -PAL_ERROR_DENIED;

    if (tf->index < 0)
        return tf->index;

#if CACHE_FILE_STUBS == 1
    if (tf->index && tf->stubs) {
        *stubptr = tf->stubs;
        *sizeptr = tf->size;
        return 0;
    }
#endif

    if (!tf->index) {
        *stubptr = NULL;
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(normpath, &attr);
        if (!ret)
            *sizeptr = attr.pending_size;
        else
            *sizeptr = 0;
        return 0;
    }

    int nstubs = tf->size / TRUSTED_STUB_SIZE +
                (tf->size % TRUSTED_STUB_SIZE ? 1 : 0);

    sgx_stub_t * stubs = malloc(sizeof(sgx_stub_t) * nstubs);
    if (!stubs)
        return -PAL_ERROR_NOMEM;

    sgx_stub_t * s = stubs; /* stubs is an array of 128bit values */
    uint64_t offset = 0;
    LIB_SHA256_CONTEXT sha;
    void * umem;

    ret = lib_SHA256Init(&sha);
    if (ret < 0)
        goto failed;

    for (; offset < tf->size ; offset += TRUSTED_STUB_SIZE, s++) {
        /* For each stub, generate a 128bit hash of a file chunk with
         * AES-CMAC, and then update the SHA256 digest. */
        uint64_t mapping_size = MIN(tf->size - offset, TRUSTED_STUB_SIZE);
        LIB_AESCMAC_CONTEXT aes_cmac;
        ret = lib_AESCMACInit(&aes_cmac, (uint8_t *) &enclave_key,
                              AES_CMAC_KEY_LEN);
        if (ret < 0)
            goto failed;

        ret = ocall_map_untrusted(fd, offset, mapping_size, PROT_READ, &umem);
        if (IS_ERR(ret)) {
            ret = unix_to_pal_error(ERRNO(ret));
            goto unmap;
        }

        /*
         * To prevent TOCTOU attack when generating the file checksum, we
         * need to copy the file content into the enclave before hashing.
         * For optimization, we use a relatively small buffer (1024 byte) to
         * store the data for checksum generation.
         */

#define FILE_CHUNK_SIZE 1024UL

        uint8_t small_chunk[FILE_CHUNK_SIZE]; /* Buffer for hashing */
        size_t chunk_offset = 0;

        for (; chunk_offset < mapping_size; chunk_offset += FILE_CHUNK_SIZE) {
            uint64_t chunk_size = MIN(mapping_size - chunk_offset, FILE_CHUNK_SIZE);

            /* Any file content needs to be copied into the enclave before
             * checking and re-hashing */
            memcpy(small_chunk, umem + chunk_offset, chunk_size);

            /* Update the file checksum */
            ret = lib_SHA256Update(&sha, small_chunk, chunk_size);
            if (ret < 0)
                goto unmap;

            /* Update the checksum for the file chunk */
            ret = lib_AESCMACUpdate(&aes_cmac, small_chunk, chunk_size);
            if (ret < 0)
                goto unmap;
        }

        /* Store the checksum for one file chunk for checking */
        ret = lib_AESCMACFinish(&aes_cmac, (uint8_t *) s, sizeof *s);
unmap:
        ocall_unmap_untrusted(umem, mapping_size);
        if (ret < 0)
            goto failed;
    }

    sgx_checksum_t hash;

    /* Finalize and checking if the checksum of the whole file matches
     * with record given in the manifest. */

    ret = lib_SHA256Final(&sha, (uint8_t *) hash.bytes);
    if (ret < 0)
        goto failed;

    if (memcmp(&hash, &tf->checksum, sizeof(sgx_checksum_t))) {
        ret = -PAL_ERROR_DENIED;
        goto failed;
    }

    _DkSpinLock(&trusted_file_lock);
    if (tf->stubs || tf->index == -PAL_ERROR_DENIED)
        free(tf->stubs);
    *stubptr = tf->stubs = stubs;
    *sizeptr = tf->size;
    ret = tf->index;
    _DkSpinUnlock(&trusted_file_lock);
    return ret;

failed:
    free(stubs);

    _DkSpinLock(&trusted_file_lock);
    if (tf->stubs) {
        *stubptr = tf->stubs;
        *sizeptr = tf->size;
        ret = tf->index;
    } else {
        tf->index = -PAL_ERROR_DENIED;
    }
    _DkSpinUnlock(&trusted_file_lock);

#if PRINT_ENCLAVE_STAT
    if (!ret) {
        sgx_stub_t * loaded_stub;
        uint64_t loaded_size;
        PAL_HANDLE handle = NULL;
        if (!_DkStreamOpen(&handle, normpath, PAL_ACCESS_RDONLY, 0, 0, 0))
            load_trusted_file (handle, &loaded_stub, &loaded_size);
    }
#endif

    return ret;
}

/*
 * A common helper function for copying and checking the file contents
 * from a buffer mapped outside the enclaves into an in-enclave buffer.
 * If needed, regions at either the beginning or the end of the copied regions
 * are copied into a scratch buffer to avoid a TOCTTOU race.
 *
 * * Note that it must be done this way to avoid the following TOCTTOU race
 * * condition with the untrusted host as an adversary:
 *       *  Adversary: put good contents in buffer
 *       *  Enclave: buffer check passes
 *       *  Adversary: put bad contents in buffer
 *       *  Enclave: copies in bad buffer contents
 *
 * * For optimization, we verify the memory in place, as the application code
 *   should not use the memory before return.  There can be subtle interactions
 *   at the edges of a region with ELF loading.  Namely, the ELF loader will
 *   want to map several file chunks that are not aligned to TRUSTED_STUB_SIZE
 *   next to each other, sometimes overlapping.  There is probably room to
 *   improve load time with more smarts around ELF loading, but for now, just
 *   make things work.
 *
 * 'umem' is the untrusted file memory mapped outside the enclave (should
 * already be mapped up by the caller). 'umem_start' and 'umem_end' are
 * the offset _within the file_ of 'umem'.  'umem_start' should be aligned
 * to the file checking chunk size (TRUSTED_STUB_SIZE). 'umem_end' can be
 * either aligned, or equal to 'total_size'. 'buffer' is the in-enclave
 * buffer for copying the file content. 'offset' is the offset within the file
 * for copying into the buffer. 'size' is the size of the in-enclave buffer.
 * 'stubs' contain the checksums of all the chunks in a file.
 */
int copy_and_verify_trusted_file (const char * path, const void * umem,
                    uint64_t umem_start, uint64_t umem_end,
                    void * buffer, uint64_t offset, uint64_t size,
                    sgx_stub_t * stubs, uint64_t total_size)
{
    /* Check that the untrusted mapping is aligned to TRUSTED_STUB_SIZE
     * and includes the range for copying into the buffer */
    assert(umem_start % TRUSTED_STUB_SIZE == 0);
    assert(offset >= umem_start && offset + size <= umem_end);

    /* Start copying and checking at umem_start. The checked content may or
     * may not be copied into the file content, depending on the offset of
     * the content within the file. */
    uint64_t checking = umem_start;
    /* The stubs is an array of 128-bit hash values of the file chunks.
     * from the beginning of the file. 's' points to the stub that needs to
     * be checked for the current offset. */
    sgx_stub_t * s = stubs + checking / TRUSTED_STUB_SIZE;
    int ret = 0;

    for (; checking < umem_end ; checking += TRUSTED_STUB_SIZE, s++) {
        /* Check one chunk at a time. */
        uint64_t checking_size = MIN(total_size - checking, TRUSTED_STUB_SIZE);
        uint64_t checking_end = checking + checking_size;
        uint8_t hash[AES_CMAC_DIGEST_LEN];

        if (checking >= offset && checking_end <= offset + size) {
            /* If the checking chunk completely overlaps with the region
             * needed for copying into the buffer, simplying use the buffer
             * for checking */
            memcpy(buffer + checking - offset, umem + checking - umem_start,
                   checking_size);

            /* Storing the checksum (using AES-CMAC) inside hash. */
            ret = lib_AESCMAC((uint8_t *) &enclave_key,
                              AES_CMAC_KEY_LEN,
                              buffer + checking - offset, checking_size,
                              hash, sizeof(hash));
        } else {
            /* If the checking chunk only partially overlaps with the region,
             * read the file content in smaller chunks and only copy the part
             * needed by the caller. */
            LIB_AESCMAC_CONTEXT aes_cmac;
            ret = lib_AESCMACInit(&aes_cmac, (uint8_t *) &enclave_key,
                                  AES_CMAC_KEY_LEN);
            if (ret < 0)
                goto failed;

            uint8_t small_chunk[FILE_CHUNK_SIZE]; /* A small buffer */
            uint64_t chunk_offset = checking;

            for (; chunk_offset < checking_end
                 ; chunk_offset += FILE_CHUNK_SIZE) {
                uint64_t chunk_size = MIN(checking_end - chunk_offset,
                                          FILE_CHUNK_SIZE);

                /* Copy into the small buffer before hashing the content */
                memcpy(small_chunk, umem + (chunk_offset - umem_start),
                       chunk_size);

                /* Update the hash for the current chunk */
                ret = lib_AESCMACUpdate(&aes_cmac, small_chunk, chunk_size);
                if (ret < 0)
                    goto failed;

                /* Determine if the part just copied and checked is needed
                 * by the caller. If so, copy it into the user buffer. */
                uint64_t copy_start = chunk_offset;
                uint64_t copy_end = copy_start + chunk_size;

                if (copy_start < offset)
                    copy_start = offset;
                if (copy_end > offset + size)
                    copy_end = offset + size;

                if (copy_end > copy_start)
                    memcpy(buffer + (copy_start - offset),
                           small_chunk + (copy_start - chunk_offset),
                           copy_end - copy_start);
            }

            /* Storing the checksum (using AES-CMAC) inside hash. */
            ret = lib_AESCMACFinish(&aes_cmac, hash, sizeof(hash));
        }

        if (ret < 0)
            goto failed;

        /*
         * Check if the hash matches with the checksum of current chunk.
         * If not, return with access denied. Note: some file content may
         * still be in the buffer (including the corrupted part).
         * We assume the user won't use the content if this function
         * returns with failures.
         *
         * XXX: Maybe we should zero the buffer after denying the access?
         */
        if (memcmp(s, hash, sizeof(sgx_stub_t))) {
            SGX_DBG(DBG_E, "Accesing file:%s is denied. Does not match with MAC"
                    " at chunk starting at %lu-%lu.\n",
                    path, checking, checking_end);
            return -PAL_ERROR_DENIED;
        }
    }

    return 0;

failed:
    return -PAL_ERROR_DENIED;
}

static int register_trusted_file (const char * uri, const char * checksum_str)
{
    struct trusted_file * tf = NULL, * new;
    int uri_len = strlen(uri);
    int ret;

    _DkSpinLock(&trusted_file_lock);

    LISTP_FOR_EACH_ENTRY(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            return 0;
        }
    }
    _DkSpinUnlock(&trusted_file_lock);

    new = malloc(sizeof(struct trusted_file));
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    new->uri_len = uri_len;
    memcpy(new->uri, uri, uri_len + 1);
    new->size = 0;
    new->stubs = NULL;

    if (checksum_str) {
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(uri, &attr);
        if (!ret)
            new->size = attr.pending_size;

        char checksum_text[sizeof(sgx_checksum_t) * 2 + 1] = "\0";
        size_t nbytes = 0;
        for (; nbytes < sizeof(sgx_checksum_t) ; nbytes++) {
            char byte1 = checksum_str[nbytes * 2];
            char byte2 = checksum_str[nbytes * 2 + 1];
            unsigned char val = 0;

            if (byte1 == 0 || byte2 == 0) {
                break;
            }
            if (!(byte1 >= '0' && byte1 <= '9') &&
                !(byte1 >= 'a' && byte1 <= 'f')) {
                break;
            }
            if (!(byte2 >= '0' && byte2 <= '9') &&
                !(byte2 >= 'a' && byte2 <= 'f')) {
                break;
            }

            if (byte1 >= '0' && byte1 <= '9')
                val = byte1 - '0';
            if (byte1 >= 'a' && byte1 <= 'f')
                val = byte1 - 'a' + 10;
            val *= 16;
            if (byte2 >= '0' && byte2 <= '9')
                val += byte2 - '0';
            if (byte2 >= 'a' && byte2 <= 'f')
                val += byte2 - 'a' + 10;

            new->checksum.bytes[nbytes] = val;
            snprintf(checksum_text + nbytes * 2, 3, "%02x", val);
        }

        if (nbytes < sizeof(sgx_checksum_t)) {
            free(new);
            return -PAL_ERROR_INVAL;
        }

        new->index = (++trusted_file_indexes);
        SGX_DBG(DBG_S, "trusted: [%ld] %s %s\n", new->index,
                checksum_text, new->uri);
    } else {
        memset(&new->checksum, 0, sizeof(sgx_checksum_t));
        new->index = 0;
        SGX_DBG(DBG_S, "allowed: %s\n", new->uri);
    }

    _DkSpinLock(&trusted_file_lock);

    LISTP_FOR_EACH_ENTRY(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            free(new);
            return 0;
        }
    }

    LISTP_ADD_TAIL(new, &trusted_file_list, list);
    _DkSpinUnlock(&trusted_file_lock);
    return 0;
}

static int init_trusted_file (const char * key, const char * uri)
{
    char cskey[URI_MAX], * tmp;
    char checksum[URI_MAX];
    char normpath[URI_MAX];

    tmp = strcpy_static(cskey, "sgx.trusted_checksum.", URI_MAX);
    memcpy(tmp, key, strlen(key) + 1);

    ssize_t len = get_config(pal_state.root_config, cskey, checksum, CONFIG_MAX);
    if (len < 0)
        return 0;

    /* Normalize the uri */
    if (!strpartcmp_static(uri, "file:")) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);
        return -PAL_ERROR_INVAL;
    }
    normpath [0] = 'f';
    normpath [1] = 'i';
    normpath [2] = 'l';
    normpath [3] = 'e';
    normpath [4] = ':';
    len = get_norm_path(uri + 5, normpath + 5, 0, URI_MAX);

    return register_trusted_file(normpath, checksum);
}

int init_trusted_files (void)
{
    struct config_store * store = pal_state.root_config;
    char * cfgbuf = NULL;
    ssize_t cfgsize;
    int nuris, ret;

    if (pal_sec.exec_name[0] != '\0') {
        ret = init_trusted_file("exec", pal_sec.exec_name);
        if (ret < 0)
            goto out;
    }

    cfgbuf = malloc(CONFIG_MAX);
    if (!cfgbuf) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    ssize_t len = get_config(store, "loader.preload", cfgbuf, CONFIG_MAX);
    if (len > 0) {
        int npreload = 0;
        char key[10];
        const char * start, * end;

        for (start = cfgbuf ; start < cfgbuf + len ; start = end + 1) {
            for (end = start ; end < cfgbuf + len && *end && *end != ',' ; end++);
            if (end > start) {
                char uri[end - start + 1];
                memcpy(uri, start, end - start);
                uri[end - start] = 0;
                snprintf(key, 10, "preload%d", npreload++);

                ret = init_trusted_file(key, uri);
                if (ret < 0)
                    goto out;
            }
        }
    }

    cfgsize = get_config_entries_size(store, "sgx.trusted_files");
    if (cfgsize <= 0)
        goto no_trusted;

    free(cfgbuf);
    cfgbuf = malloc(cfgsize);
    if (!cfgbuf) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }


    nuris = get_config_entries(store, "sgx.trusted_files", cfgbuf, cfgsize);
    if (nuris <= 0)
        goto no_trusted;

    {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.trusted_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(store, key, uri, CONFIG_MAX);
            if (len > 0) {
                ret = init_trusted_file(key + 18, uri);
                if (ret < 0)
                    goto out;
            }
        }
    }

no_trusted:

    cfgsize = get_config_entries_size(store, "sgx.allowed_files");
    if (cfgsize <= 0)
        goto no_allowed;

    free(cfgbuf);
    cfgbuf = malloc(cfgsize);
    if (!cfgbuf) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    nuris = get_config_entries(store, "sgx.allowed_files", cfgbuf, cfgsize);
    if (nuris <= 0)
        goto no_allowed;

    {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.allowed_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(store, key, uri, CONFIG_MAX);
            if (len > 0)
                register_trusted_file(uri, NULL);
        }
    }

no_allowed:
    ret = 0;

    if (get_config(store, "sgx.allow_file_creation", cfgbuf, CONFIG_MAX) <= 0) {
        allow_file_creation = false;
    } else
        allow_file_creation = true;

out:
    free(cfgbuf);
    return ret;
}

int init_trusted_children (void)
{
    struct config_store * store = pal_state.root_config;

    char key[CONFIG_MAX], mrkey[CONFIG_MAX];
    char uri[CONFIG_MAX], mrenclave[CONFIG_MAX];

    char * tmp1 = strcpy_static(key, "sgx.trusted_children.", CONFIG_MAX);
    char * tmp2 = strcpy_static(mrkey, "sgx.trusted_mrenclave.", CONFIG_MAX);

    ssize_t cfgsize = get_config_entries_size(store, "sgx.trusted_mrenclave");
    if (cfgsize <= 0)
        return 0;

    char * cfgbuf = malloc(cfgsize);
    if (!cfgbuf)
        return -PAL_ERROR_NOMEM;

    int nuris = get_config_entries(store, "sgx.trusted_mrenclave",
                                   cfgbuf, cfgsize);
    if (nuris > 0) {
        char * k = cfgbuf;
        for (int i = 0 ; i < nuris ; i++) {
            int len = strlen(k);
            memcpy(tmp1, k, len + 1);
            memcpy(tmp2, k, len + 1);
            k += len + 1;

            ssize_t ret = get_config(store, key, uri, CONFIG_MAX);
            if (ret < 0)
                continue;

            ret = get_config(store, mrkey, mrenclave, CONFIG_MAX);
            if (ret > 0)
                register_trusted_child(uri, mrenclave);
        }
    }
    free(cfgbuf);
    return 0;
}

#if 0
void test_dh (void)
{
    int ret;
    DhKey key1, key2;
    uint32_t privsz1, privsz2, pubsz1, pubsz2, agreesz1, agreesz2;
    unsigned char priv1[128], pub1[128], priv2[128], pub2[128], agree1[128],
        agree2[128], scratch[257];

    InitDhKey(&key1);
    InitDhKey(&key2);

    ret = DhSetKey(&key1, dh_param.p, sizeof(dh_param.p), dh_param.g,
                   sizeof(dh_param.g));
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhSetKey for key 1 failed: %d\n", ret);
        return;
    }
    ret = DhSetKey(&key2, dh_param.p, sizeof(dh_param.p), dh_param.g,
                   sizeof(dh_param.g));
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhSetKey for key 2 failed: %d\n", ret);
        return;
    }

    ret = DhGenerateKeyPair(&key1, priv1, &privsz1, pub1, &pubsz1);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhGenerateKeyPair for key 1 failed: %d\n", ret);
        return;
    }
    ret = DhGenerateKeyPair(&key2, priv2, &privsz2, pub2, &pubsz2);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhGenerateKeyPair for key 2 failed: %d\n", ret);
        return;
    }

    ret = DhAgree(&key1, agree1, &agreesz1, priv1, privsz1, pub2, pubsz2);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhAgree for key 1 failed: %d\n", ret);
        return;
    }

    ret = DhAgree(&key2, agree2, &agreesz2, priv2, privsz2, pub1, pubsz1);
    if (ret < 0) {
        SGX_DBG(DBG_S, "DhAgree for key 1 failed: %d\n", ret);
        return;
    }

    FreeDhKey(&key1);
    FreeDhKey(&key2);

    SGX_DBG(DBG_S, "key exchange(side A): %s\n",
            __bytes2hexstr(agree1, agreesz1, scratch, agreesz1 * 2 + 1));
    SGX_DBG(DBG_S, "key exchange(side B): %s\n",
            __bytes2hexstr(agree2, agreesz2, scratch, agreesz2 * 2 + 1));
}
#endif

#define RSA_KEY_SIZE        2048
#define RSA_E               3

int init_enclave (void)
{
    // Get report to initialize info (MRENCLAVE, etc.) about this enclave from
    // a trusted source.

    // Since this report is only read by ourselves we can
    // leave targetinfo zeroed.
    sgx_arch_targetinfo_t targetinfo = {0};
    struct pal_enclave_state reportdata = {0};
    sgx_arch_report_t report;

    int ret = sgx_report(&targetinfo, &reportdata, &report);
    if (ret) {
        SGX_DBG(DBG_E, "failed to get self report: %d\n", ret);
        return -PAL_ERROR_INVAL;
    }
    memcpy(pal_sec.mrenclave, report.body.mrenclave, sizeof(pal_sec.mrenclave));
    memcpy(pal_sec.mrsigner, report.body.mrsigner, sizeof(pal_sec.mrsigner));
    pal_sec.enclave_attributes = report.body.attributes;

#if 0
    /*
     * This enclave-specific key is a building block for authenticating
     * new pipe connections with other enclaves that are already
     * authenticated. Since pipe protection is a future feature, this key
     * is currently unused and hence deprecated.
     */
    int ret;
    LIB_RSA_KEY *rsa = malloc(sizeof(LIB_RSA_KEY));
    lib_RSAInitKey(rsa);

    ret = lib_RSAGenerateKey(rsa, RSA_KEY_SIZE, RSA_E);
    if (ret < 0) {
        SGX_DBG(DBG_S, "lib_RSAGenerateKey failed: %d\n", ret);
        return ret;
    }

    pal_enclave_config.enclave_key = rsa;
#endif

    /*
     * The enclave identifier is uniquely created for each enclave as a token
     * for authenticating the enclave as the sender of attestation.
     * TODO: documenting the inter-enclave attestation protocol.
     */
    _DkRandomBitsRead(&pal_enclave_state.enclave_identifier,
                      sizeof(pal_enclave_state.enclave_identifier));

    SGX_DBG(DBG_S, "enclave (software) key hash: %s\n",
            ALLOCA_BYTES2HEXSTR(pal_enclave_state.enclave_identifier));

    return 0;
}

int _DkStreamKeyExchange (PAL_HANDLE stream, PAL_SESSION_KEY * keyptr)
{
    uint8_t session_key[sizeof(PAL_SESSION_KEY)]
        __attribute__((aligned(sizeof(PAL_SESSION_KEY))));
    uint8_t pub[DH_SIZE]   __attribute__((aligned(DH_SIZE)));
    uint8_t agree[DH_SIZE] __attribute__((aligned(DH_SIZE)));
    PAL_NUM pubsz, agreesz;
    LIB_DH_CONTEXT context;
    int ret;

    ret = lib_DhInit(&context);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH Init failed: %d\n", ret);
        goto out_no_final;
    }

    pubsz = sizeof pub;
    ret = lib_DhCreatePublic(&context, pub, &pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH CreatePublic failed: %d\n", ret);
        goto out;
    }

    assert(pubsz > 0 && pubsz <= DH_SIZE);
    if (pubsz < DH_SIZE) {
        /* Insert leading zero bytes if necessary. These values are big-
         * endian, so we either need to know the length of the bignum or
         * zero-pad at the beginning instead of the end. This code chooses
         * to do the latter. */
        memmove(pub + (DH_SIZE - pubsz), pub, pubsz);
        memset(pub, 0, DH_SIZE - pubsz);
    }

    ret = _DkStreamWrite(stream, 0, DH_SIZE, pub, NULL, 0);
    if (ret != DH_SIZE) {
        SGX_DBG(DBG_S, "Key Exchange: DkStreamWrite failed: %d\n", ret);
        goto out;
    }

    ret = _DkStreamRead(stream, 0, DH_SIZE, pub, NULL, 0);
    if (ret != DH_SIZE) {
        SGX_DBG(DBG_S, "Key Exchange: DkStreamRead failed: %d\n", ret);
        goto out;
    }

    agreesz = sizeof agree;
    ret = lib_DhCalcSecret(&context, pub, DH_SIZE, agree, &agreesz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DH CalcSecret failed: %d\n", ret);
        goto out;
    }

    assert(agreesz > 0 && agreesz <= sizeof agree);
    // TODO(security): use a real KDF
    memset(session_key, 0, sizeof(session_key));
    for (uint32_t i = 0 ; i < agreesz ; i++)
        session_key[i % sizeof(session_key)] ^= agree[i];

    SGX_DBG(DBG_S, "key exchange: (%p) %s\n", session_key,
            ALLOCA_BYTES2HEXSTR(session_key));

    if (keyptr)
        memcpy(keyptr, session_key, sizeof(PAL_SESSION_KEY));

    ret = 0;
out:
    lib_DhFinal(&context);
out_no_final:
    return ret;
}

struct attestation_request {
    sgx_arch_hash_t       mrenclave;
    sgx_arch_attributes_t attributes;
};

struct attestation {
    sgx_arch_hash_t       mrenclave;
    sgx_arch_attributes_t attributes;
    sgx_arch_report_t     report;
};

int _DkStreamAttestationRequest (PAL_HANDLE stream, void * data,
                                 int (*check_mrenclave) (sgx_arch_hash_t *,
                                                         void *, void *),
                                 void * check_param)
{
    struct attestation_request req;
    struct attestation att;
    size_t bytes;
    int ret;

    memcpy(req.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&req.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation request ... (mrenclave = %s)\n",\
            ALLOCA_BYTES2HEXSTR(req.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(req) ; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(req) - bytes,
                             ((void *) &req) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: DkStreamWrite failed: %d\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(att) - bytes,
                            ((void *) &att) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: DkStreamRead failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation (mrenclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(att.mrenclave));

    ret = sgx_verify_report(&att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: sgx_verify_report failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Remote attestation not signed by SGX!\n");
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    ret = check_mrenclave(&att.report.body.mrenclave, &att.report.body.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check_mrenclave failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed enclave (mrenclave = %s)\n",
                ALLOCA_BYTES2HEXSTR(att.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Remote attestation succeed!\n");

    ret = sgx_get_report(&att.mrenclave, &att.attributes, data, &att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: sgx_get_report failed: %d\n", ret);
        goto out;
    }

    memcpy(att.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&att.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation ... (mrenclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(att.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(att) - bytes,
                             ((void *) &att) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Request: DkStreamWrite failed: %d\n", ret);
            goto out;
        }
    }

    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

int _DkStreamAttestationRespond (PAL_HANDLE stream, void * data,
                                 int (*check_mrenclave) (sgx_arch_hash_t *,
                                                         void *, void *),
                                 void * check_param)
{
    struct attestation_request req;
    struct attestation att;
    size_t bytes;
    int ret;

    for (bytes = 0, ret = 0 ; bytes < sizeof(req) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(req) - bytes,
                            ((void *) &req) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: DkStreamRead failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation request ... (mrenclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(req.mrenclave));

    ret = sgx_get_report(&req.mrenclave, &req.attributes, data, &att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: sgx_get_report failed: %d\n", ret);
        goto out;
    }

    memcpy(att.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&att.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation ... (mrenclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(att.mrenclave));

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(att) - bytes,
                             ((void *) &att) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: DkStreamWrite failed: %d\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(att) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(att) - bytes,
                            ((void *) &att) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: DkStreamRead failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation (mrenclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(att.mrenclave));

    ret = sgx_verify_report(&att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: sgx_verify_report failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Remote attestation not signed by SGX!\n");
        goto out;
    }

    ret = check_mrenclave(&att.report.body.mrenclave, &att.report.body.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check_mrenclave failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed enclave (mrenclave = %s)\n",
                ALLOCA_BYTES2HEXSTR(att.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Remote attestation succeeded!\n");
    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

/*
 * Restore an sgx_context_t as generated by .Lhandle_exception. Execution will
 * continue as specified by the rip in the context.
 *
 * It is required that:
 *
 *     ctx == ctx->rsp - (sizeof(sgx_context_t) + RED_ZONE_SIZE)
 *
 * This means that the ctx is allocated directly below the "normal" stack
 * (honoring its red zone). This is needed to properly restore the old state
 * (see _restore_sgx_context for details).
 *
 * For the original sgx_context_t allocated by .Lhandle_exception this is true.
 * This is a safe wrapper around _restore_sgx_context, which checks this
 * preconditon.
 */
void restore_sgx_context(sgx_context_t *ctx) {
    if (((uint64_t) ctx) != ctx->rsp - (sizeof(sgx_context_t) + RED_ZONE_SIZE)) {
        SGX_DBG(DBG_E, "Invalid sgx_context_t pointer passed to restore_sgx_context!\n");
        ocall_exit(1);
    }

    _restore_sgx_context(ctx);
}
