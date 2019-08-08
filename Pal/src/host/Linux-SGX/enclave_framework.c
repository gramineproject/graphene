/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>
#include <list.h>

#include "enclave_pages.h"

struct pal_enclave_state pal_enclave_state;

void * enclave_base, * enclave_top;

struct pal_enclave_config pal_enclave_config;

static int register_trusted_file (const char * uri, const char * checksum_str);

bool sgx_is_within_enclave (const void * addr, uint64_t size)
{
    return enclave_base <= addr && addr + size <= enclave_top;
}

void * sgx_ocalloc (uint64_t size)
{
    void * ustack = GET_ENCLAVE_TLS(ustack) - size;
    SET_ENCLAVE_TLS(ustack, ustack);
    return ustack;
}

void sgx_ocfree (void)
{
    SET_ENCLAVE_TLS(ustack, GET_ENCLAVE_TLS(ustack_top));
}

static sgx_arch_key128_t enclave_key;

#define KEYBUF_SIZE ((sizeof(sgx_arch_key128_t) * 2) + 1)

/*
 * sgx_get_report() obtains a CPU-signed report for local attestation
 * @target_info:  the enclave target info
 * @enclave_data: the data to be included and signed in the report
 * @report:       a buffer for storing the report
 */
static int sgx_get_report(sgx_arch_targetinfo_t* target_info, sgx_sign_data_t* data,
                          sgx_arch_report_t* report) {
    struct pal_enclave_state state;
    memcpy(&state, &pal_enclave_state, sizeof(state));
    memcpy(&state.enclave_data, data, sizeof(*data));

    int ret = sgx_report(target_info, &state, report);
    if (ret) {
        SGX_DBG(DBG_E, "sgx_report failed: ret = %d)\n", ret);
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Generated report:\n");
    SGX_DBG(DBG_S, "    cpusvn:           %08x %08x\n", report->cpusvn[0],
                                                report->cpusvn[1]);
    SGX_DBG(DBG_S, "    mrenclave:        %s\n",        alloca_bytes2hexstr(report->mrenclave));
    SGX_DBG(DBG_S, "    mrsigner:         %s\n",        alloca_bytes2hexstr(report->mrsigner));
    SGX_DBG(DBG_S, "    attributes.flags: %016lx\n",    report->attributes.flags);
    SGX_DBG(DBG_S, "    sttributes.xfrm:  %016lx\n",    report->attributes.xfrm);

    SGX_DBG(DBG_S, "    isvprodid:        %02x\n",      report->isvprodid);
    SGX_DBG(DBG_S, "    isvsvn:           %02x\n",      report->isvsvn);
    SGX_DBG(DBG_S, "    keyid:            %s\n",        alloca_bytes2hexstr(report->keyid));
    SGX_DBG(DBG_S, "    mac:              %s\n",        alloca_bytes2hexstr(report->mac));

    return 0;
}

int sgx_verify_report (sgx_arch_report_t * report)
{
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = REPORT_KEY;
    memcpy(keyrequest.keyid, report->keyid, sizeof(keyrequest.keyid));

    sgx_arch_key128_t report_key;
    memset(&report_key, 0, sizeof(sgx_arch_key128_t));

    int ret = sgx_getkey(&keyrequest, &report_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get report key for verification: %s\n", alloca_bytes2hexstr(report_key));

    sgx_arch_mac_t check_mac;
    memset(&check_mac, 0, sizeof(sgx_arch_mac_t));

    lib_AESCMAC((uint8_t *) &report_key, sizeof(report_key),
                (uint8_t *) report, offsetof(sgx_arch_report_t, keyid),
                (uint8_t *) &check_mac, sizeof(sgx_arch_mac_t));

    memset(&report_key, 0, sizeof(sgx_arch_key128_t));

    SGX_DBG(DBG_S, "Verify report:\n");
    SGX_DBG(DBG_S, "    expected:         %s\n", alloca_bytes2hexstr(report->mac));
    SGX_DBG(DBG_S, "    mac:              %s\n", alloca_bytes2hexstr(check_mac));

    if (memcmp(&check_mac, &report->mac, sizeof(check_mac))) {
        SGX_DBG(DBG_S, "Report verification failed\n");
        return -PAL_ERROR_DENIED;
    }

    return 0;
}

int init_enclave_key (void)
{
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = SEAL_KEY;

    int ret = sgx_getkey(&keyrequest, &enclave_key);
    if (ret) {
        SGX_DBG(DBG_E, "Can't get seal key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Seal key: %s\n", alloca_bytes2hexstr(enclave_key));
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
static int allow_file_creation = 0;


/*
 * 'load_trusted_file' checks if the file to be opened is trusted
 * or allowed for unauthenticated access, according to the manifest.
 *
 * file:     file handle to be opened
 * stubptr:  buffer for catching matched file stub.
 * sizeptr:  size pointer
 * create:   this file is newly created or not
 *
 * Return 0 if succeeded, or an error code.
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

    listp_for_each_entry(tmp, &trusted_file_list, list) {
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
        ret = lib_AESCMACInit(&aes_cmac, (uint8_t*)&enclave_key, sizeof(enclave_key));
        if (ret < 0)
            goto failed;

        ret = ocall_map_untrusted(fd, offset, mapping_size, PROT_READ, &umem);
        if (ret < 0)
            goto unmap;

        /*
         * To prevent TOCTOU attack when generating the file checksum, we
         * need to copy the file content into the enclave before hashing.
         * For optimization, we use a relatively small buffer (1024 byte) to
         * store the data for checksum generation.
         */

#define FILE_CHUNK_SIZE 1024

        uint8_t small_chunk[FILE_CHUNK_SIZE]; /* Buffer for hashing */
        int chunk_offset = 0;

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
        sgx_checksum_t hash;

        if (checking >= offset && checking_end <= offset + size) {
            /* If the checking chunk completely overlaps with the region
             * needed for copying into the buffer, simplying use the buffer
             * for checking */
            memcpy(buffer + checking - offset, umem + checking - umem_start,
                   checking_size);

            /* Storing the checksum (using AES-CMAC) inside hash. */
            ret = lib_AESCMAC((uint8_t*)&enclave_key, sizeof(enclave_key),
                              buffer + checking - offset, checking_size,
                              (uint8_t*)&hash, sizeof(hash));
        } else {
            /* If the checking chunk only partially overlaps with the region,
             * read the file content in smaller chunks and only copy the part
             * needed by the caller. */
            LIB_AESCMAC_CONTEXT aes_cmac;
            ret = lib_AESCMACInit(&aes_cmac, (uint8_t*)&enclave_key, sizeof(enclave_key));
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
            ret = lib_AESCMACFinish(&aes_cmac, (uint8_t*)&hash, sizeof(hash));
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
        if (memcmp(s, &hash, sizeof(sgx_stub_t))) {
            SGX_DBG(DBG_E, "Accesing file:%s is denied. Does not match with MAC"
                    " at chunk starting at %llu-%llu.\n",
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

    listp_for_each_entry(tf, &trusted_file_list, list) {
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
        int nbytes = 0;
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
        SGX_DBG(DBG_S, "trusted: [%d] %s %s\n", new->index,
                checksum_text, new->uri);
    } else {
        memset(&new->checksum, 0, sizeof(sgx_checksum_t));
        new->index = 0;
        SGX_DBG(DBG_S, "allowed: %s\n", new->uri);
    }

    _DkSpinLock(&trusted_file_lock);

    listp_for_each_entry(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            free(new);
            return 0;
        }
    }

    listp_add_tail(new, &trusted_file_list, list);
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

    if (pal_sec.exec_fd != PAL_IDX_POISON) {
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
        allow_file_creation = 0;
    } else
        allow_file_creation = 1;

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
     * The enclave id is uniquely created for each enclave as a token
     * for authenticating the enclave as the sender of attestation.
     * See 'host/Linux-SGX/db_process.c' for further explanation.
     */
    _DkRandomBitsRead(&pal_enclave_state.enclave_id,
                      sizeof(pal_enclave_state.enclave_id));

    return 0;
}

int _DkStreamKeyExchange(PAL_HANDLE stream, PAL_SESSION_KEY* key) {
    uint8_t pub[DH_SIZE]   __attribute__((aligned(DH_SIZE)));
    uint8_t agree[DH_SIZE] __attribute__((aligned(DH_SIZE)));
    PAL_NUM pubsz, agreesz;
    LIB_DH_CONTEXT context;
    int ret;

    ret = lib_DhInit(&context);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH Init failed: %d\n", ret);
        goto out_no_final;
    }

    pubsz = sizeof pub;
    ret = lib_DhCreatePublic(&context, pub, &pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH CreatePublic failed: %d\n", ret);
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
        SGX_DBG(DBG_E, "Key Exchange: DkStreamWrite failed: %d\n", ret);
        goto out;
    }

    ret = _DkStreamRead(stream, 0, DH_SIZE, pub, NULL, 0);
    if (ret != DH_SIZE) {
        SGX_DBG(DBG_E, "Key Exchange: DkStreamRead failed: %d\n", ret);
        goto out;
    }

    agreesz = sizeof agree;
    ret = lib_DhCalcSecret(&context, pub, DH_SIZE, agree, &agreesz);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH CalcSecret failed: %d\n", ret);
        goto out;
    }

    assert(agreesz > 0 && agreesz <= sizeof agree);

    /* Using SHA256 as a KDF to convert the 128-byte DH secret to a 256-bit AES key. */
    LIB_SHA256_CONTEXT sha;
    if ((ret = lib_SHA256Init(&sha)) < 0 ||
        (ret = lib_SHA256Update(&sha, agree, agreesz)) < 0 ||
        (ret = lib_SHA256Final(&sha, (uint8_t*)key)) < 0) {
        SGX_DBG(DBG_E, "Failed to derive the session key: %s\n", ret);
        goto out;
    }


    SGX_DBG(DBG_S, "Key exchange succeeded: %s\n", alloca_bytes2hexstr(*key));
    ret = 0;
out:
    lib_DhFinal(&context);
out_no_final:
    return ret;
}

/* Assuming the caller to be A */
int _DkStreamReportRequest(PAL_HANDLE stream, sgx_sign_data_t* data,
                           check_mrenclave_t check_mrenclave) {
    sgx_arch_targetinfo_t target_info;
    sgx_arch_report_t report;
    int bytes, ret;

    /* A -> B: targetinfo[A] */
    memset(&target_info, 0, sizeof(sgx_arch_targetinfo_t));
    memcpy(&target_info.mrenclave,  &pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&target_info.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    for (bytes = 0, ret = 0; bytes < SGX_TARGETINFO_FILLED_SIZE; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, SGX_TARGETINFO_FILLED_SIZE - bytes,
                             ((void*)&target_info) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to send target info via RPC: %d\n", ret);
            goto out;
        }
    }

    /* B -> A: report[B -> A] */
    for (bytes = 0, ret = 0 ; bytes < sizeof(report) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(report) - bytes,
                            ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to receive local report via RPC: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received local report (mrenclave = %s)\n",
            alloca_bytes2hexstr(report.mrenclave));

    /* Verify report[B -> A] */
    ret = sgx_verify_report(&report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to verify local report: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E, "Local report is not signed by CPU\n");
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    struct pal_enclave_state* remote_state = (void*)&report.report_data;
    ret = check_mrenclave(stream, &report.mrenclave, remote_state);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to check local report: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E, "Not an allowed enclave (mrenclave = %s)\n",
                alloca_bytes2hexstr(report.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Local attestation succeeded!\n");

    /* A -> B: report[A -> B] */
    memcpy(&target_info.mrenclave , &report.mrenclave,  sizeof(sgx_arch_hash_t));
    memcpy(&target_info.attributes, &report.attributes, sizeof(sgx_arch_attributes_t));

    ret = sgx_get_report(&target_info, data, &report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get local report from CPU: %d\n", ret);
        goto out;
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(report) ; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(report) - bytes,
                             ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to send local report via RPC: %d\n", ret);
            goto out;
        }
    }

    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

/* Assuming the caller to be B */
int _DkStreamReportRespond(PAL_HANDLE stream, sgx_sign_data_t* data,
                           check_mrenclave_t check_mrenclave) {
    sgx_arch_targetinfo_t target_info;
    sgx_arch_report_t report;
    int bytes, ret;
    memset(&target_info, 0, sizeof(target_info));

    /* A -> B: targetinfo[A] */
    for (bytes = 0, ret = 0 ; bytes < SGX_TARGETINFO_FILLED_SIZE ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, SGX_TARGETINFO_FILLED_SIZE - bytes,
                            ((void*)&target_info) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to receive target info via RPC: %d\n", ret);
            goto out;
        }
    }

    /* B -> A: report[B -> A] */
    ret = sgx_get_report(&target_info, data, &report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get local report from CPU: %d\n", ret);
        goto out;
    }

    for (bytes = 0, ret = 0 ; bytes < sizeof(report) ; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(report) - bytes,
                             ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to send local report via PRC: %d\n", ret);
            goto out;
        }
    }

    /* A -> B: report[A -> B] */
    for (bytes = 0, ret = 0 ; bytes < sizeof(report) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(report) - bytes,
                            ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Failed to receive local report via RPC: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received local report (mrenclave = %s)\n",
            alloca_bytes2hexstr(report.mrenclave));

    /* Verify report[A -> B] */
    ret = sgx_verify_report(&report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to verify local report: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E, "Local report is not signed by CPU.\n");
        goto out;
    }

    struct pal_enclave_state* remote_state = (void*)&report.report_data;
    ret = check_mrenclave(stream, &report.mrenclave, remote_state);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to check mrenclave: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E, "Not an allowed enclave (mrenclave = %s)\n",
                alloca_bytes2hexstr(report.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Local attestation succeeded!\n");
    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}
