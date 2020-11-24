#include <stdbool.h>

#include "api.h"
#include "enclave_pages.h"
#include "hex.h"
#include "list.h"
#include "pal_crypto.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_security.h"
#include "spinlock.h"
#include "toml.h"

__sgx_mem_aligned struct pal_enclave_state g_pal_enclave_state;

void* g_enclave_base;
void* g_enclave_top;

static int register_trusted_file(const char* uri, const char* checksum_str, bool check_duplicates);

bool sgx_is_completely_within_enclave(const void* addr, size_t size) {
    if ((uintptr_t)addr > UINTPTR_MAX - size) {
        return false;
    }

    return g_enclave_base <= addr && addr + size <= g_enclave_top;
}

bool sgx_is_completely_outside_enclave(const void* addr, size_t size) {
    if ((uintptr_t)addr > UINTPTR_MAX - size) {
        return false;
    }

    return g_enclave_base >= addr + size || g_enclave_top <= addr;
}

/*
 * When DEBUG is enabled, we run sgx_profile_sample() during asynchronous enclave exit (AEX), which
 * uses the stack. Make sure to update URSP so that the AEX handler does not overwrite the part of
 * the stack that we just allocated.
 *
 * (Recall that URSP is an outside stack pointer, saved by EENTER and restored on AEX by the SGX
 * hardware itself.)
 */
#ifdef DEBUG

#define UPDATE_USTACK(_ustack)                           \
    do {                                                 \
        SET_ENCLAVE_TLS(ustack, _ustack);                \
        GET_ENCLAVE_TLS(gpr)->ursp = (uint64_t)_ustack;  \
    } while(0)

#else

#define UPDATE_USTACK(_ustack) SET_ENCLAVE_TLS(ustack, _ustack)

#endif

void* sgx_prepare_ustack(void) {
    void* old_ustack = GET_ENCLAVE_TLS(ustack);

    void* ustack = old_ustack;
    if (ustack != GET_ENCLAVE_TLS(ustack_top))
        ustack -= RED_ZONE_SIZE;
    UPDATE_USTACK(ustack);

    return old_ustack;
}

void* sgx_alloc_on_ustack_aligned(size_t size, size_t alignment) {
    assert(IS_POWER_OF_2(alignment));
    void* ustack = GET_ENCLAVE_TLS(ustack) - size;
    ustack = ALIGN_DOWN_PTR_POW2(ustack, alignment);
    if (!sgx_is_completely_outside_enclave(ustack, size)) {
        return NULL;
    }
    UPDATE_USTACK(ustack);
    return ustack;
}

void* sgx_alloc_on_ustack(size_t size) {
    return sgx_alloc_on_ustack_aligned(size, 1);
}

void* sgx_copy_to_ustack(const void* ptr, size_t size) {
    if (!sgx_is_completely_within_enclave(ptr, size)) {
        return NULL;
    }
    void* uptr = sgx_alloc_on_ustack(size);
    if (uptr) {
        memcpy(uptr, ptr, size);
    }
    return uptr;
}

void sgx_reset_ustack(const void* old_ustack) {
    assert(old_ustack <= GET_ENCLAVE_TLS(ustack_top));
    UPDATE_USTACK(old_ustack);
}

bool sgx_copy_ptr_to_enclave(void** ptr, void* uptr, size_t size) {
    assert(ptr);
    if (!sgx_is_completely_outside_enclave(uptr, size)) {
        *ptr = NULL;
        return false;
    }
    *ptr = uptr;
    return true;
}

bool sgx_copy_to_enclave(void* ptr, size_t maxsize, const void* uptr, size_t usize) {
    if (usize > maxsize ||
        !sgx_is_completely_outside_enclave(uptr, usize) ||
        !sgx_is_completely_within_enclave(ptr, usize)) {
        return false;
    }
    memcpy(ptr, uptr, usize);
    return true;
}

static void print_report(sgx_report_t* r) {
    SGX_DBG(DBG_S, "  cpu_svn:     %s\n",     ALLOCA_BYTES2HEXSTR(r->body.cpu_svn.svn));
    SGX_DBG(DBG_S, "  mr_enclave:  %s\n",     ALLOCA_BYTES2HEXSTR(r->body.mr_enclave.m));
    SGX_DBG(DBG_S, "  mr_signer:   %s\n",     ALLOCA_BYTES2HEXSTR(r->body.mr_signer.m));
    SGX_DBG(DBG_S, "  attr.flags:  %016lx\n", r->body.attributes.flags);
    SGX_DBG(DBG_S, "  attr.xfrm:   %016lx\n", r->body.attributes.xfrm);
    SGX_DBG(DBG_S, "  isv_prod_id: %02x\n",   r->body.isv_prod_id);
    SGX_DBG(DBG_S, "  isv_svn:     %02x\n",   r->body.isv_svn);
    SGX_DBG(DBG_S, "  report_data: %s\n",     ALLOCA_BYTES2HEXSTR(r->body.report_data.d));
    SGX_DBG(DBG_S, "  key_id:      %s\n",     ALLOCA_BYTES2HEXSTR(r->key_id.id));
    SGX_DBG(DBG_S, "  mac:         %s\n",     ALLOCA_BYTES2HEXSTR(r->mac));
}

static sgx_key_128bit_t g_enclave_key;

static int __sgx_get_report(sgx_target_info_t* target_info, sgx_sign_data_t* data,
                            sgx_report_t* report) {
    __sgx_mem_aligned struct pal_enclave_state state;
    memcpy(&state, &g_pal_enclave_state, sizeof(state));
    memcpy(&state.enclave_data, data, sizeof(*data));

    int ret = sgx_report(target_info, &state, report);
    if (ret) {
        SGX_DBG(DBG_E, "sgx_report failed: ret = %d)\n", ret);
        return -PAL_ERROR_DENIED;
    }

    print_report(report);
    return 0;
}

int sgx_get_report(const sgx_target_info_t* target_info, const sgx_report_data_t* data,
                   sgx_report_t* report) {
    int ret = sgx_report(target_info, data, report);
    if (ret) {
        SGX_DBG(DBG_E, "sgx_report failed: ret = %d\n", ret);
        return -PAL_ERROR_DENIED;
    }
    return 0;
}

int sgx_verify_report(sgx_report_t* report) {
    __sgx_mem_aligned sgx_key_request_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_key_request_t));
    keyrequest.key_name = REPORT_KEY;
    memcpy(&keyrequest.key_id, &report->key_id, sizeof(keyrequest.key_id));

    sgx_key_128bit_t report_key __attribute__((aligned(sizeof(sgx_key_128bit_t))));
    memset(&report_key, 0, sizeof(report_key));

    int ret = sgx_getkey(&keyrequest, &report_key);
    if (ret) {
        SGX_DBG(DBG_E, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get report key for verification: %s\n", ALLOCA_BYTES2HEXSTR(report_key));

    sgx_mac_t check_mac;
    memset(&check_mac, 0, sizeof(check_mac));

    // Generating the MAC with AES-CMAC using the report key. Only hash the part of the report
    // BEFORE the keyid field (hence the offsetof(...) trick). ENCLU[EREPORT] does not include
    // the MAC and the keyid fields when generating the MAC.
    lib_AESCMAC((uint8_t*)&report_key, sizeof(report_key),
                (uint8_t*)report, offsetof(sgx_report_t, key_id),
                (uint8_t*)&check_mac, sizeof(check_mac));

    // Clear the report key for security
    memset(&report_key, 0, sizeof(report_key));

    SGX_DBG(DBG_S, "Verify report:\n");
    print_report(report);
    SGX_DBG(DBG_S, "  verify:     %s\n", ALLOCA_BYTES2HEXSTR(check_mac));

    if (memcmp(&check_mac, &report->mac, sizeof(check_mac))) {
        SGX_DBG(DBG_E, "Report verification failed\n");
        return -PAL_ERROR_DENIED;
    }

    return 0;
}

int init_enclave_key(void) {
    __sgx_mem_aligned sgx_key_request_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_key_request_t));
    keyrequest.key_name = SEAL_KEY;

    int ret = sgx_getkey(&keyrequest, &g_enclave_key);
    if (ret) {
        SGX_DBG(DBG_E, "Can't get seal key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Seal key: %s\n", ALLOCA_BYTES2HEXSTR(g_enclave_key));
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
    uint64_t size;
    bool allowed;
    sgx_checksum_t checksum;
    sgx_stub_t* stubs;
    size_t uri_len;
    char uri[]; /* must be NULL-terminated */
};

DEFINE_LISTP(trusted_file);
static LISTP_TYPE(trusted_file) g_trusted_file_list = LISTP_INIT;
static spinlock_t g_trusted_file_lock = INIT_SPINLOCK_UNLOCKED;
static int g_file_check_policy = FILE_CHECK_POLICY_STRICT;

/* Assumes `path` is normalized */
static bool path_is_equal_or_subpath(const struct trusted_file* tf, const char* path,
                                     size_t path_len) {
    if (tf->uri_len > path_len || memcmp(tf->uri, path, tf->uri_len)) {
        /* tf->uri is not prefix of `path` */
        return false;
    }
    if (tf->uri_len == path_len) {
        /* Both are equal */
        return true;
    }
    if (tf->uri[tf->uri_len - 1] == '/' || path[tf->uri_len] == '/') {
        /* tf->uri is a subpath of `path` */
        return true;
    }
    if (tf->uri_len == URI_PREFIX_FILE_LEN &&
            !memcmp(tf->uri, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN)) {
        /* Empty path is a prefix of everything */
        return true;
    }
    return false;
}

/*
 * 'load_trusted_file' checks if the file to be opened is trusted
 * or allowed for unauthenticated access, according to the manifest.
 *
 * file:     file handle to be opened
 * stubptr:  buffer for catching matched file stub.
 * sizeptr:  size pointer
 * create:   this file is newly created or not
 *
 * Returns 0 if succeeded, or an error code otherwise.
 */
int load_trusted_file(PAL_HANDLE file, sgx_stub_t** stubptr, uint64_t* sizeptr, int create,
                      void** umem) {
    *stubptr = NULL;
    *sizeptr = 0;
    *umem = NULL;

    struct trusted_file* tf = NULL;
    struct trusted_file* tmp;
    char uri[URI_MAX];
    char normpath[URI_MAX];
    int ret, fd = file->file.fd;

    if (!(HANDLE_HDR(file)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    ret = _DkStreamGetName(file, uri, URI_MAX);
    if (ret < 0) {
        return ret;
    }

    /* always allow creating files */
    if (create) {
        register_trusted_file(uri, NULL, /*check_duplicates=*/true);
        return 0;
    }

    /* Normalize the uri */
    if (!strstartswith(uri, URI_PREFIX_FILE)) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);
        return -PAL_ERROR_INVAL;
    }
    static_assert(sizeof(normpath) > URI_PREFIX_FILE_LEN, "`normpath` is too small");
    memcpy(normpath, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN);
    size_t len = sizeof(normpath) - URI_PREFIX_FILE_LEN;
    ret = get_norm_path(uri + URI_PREFIX_FILE_LEN, normpath + URI_PREFIX_FILE_LEN, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Path (%s) normalization failed: %s\n", uri + URI_PREFIX_FILE_LEN,
                pal_strerror(-ret));
        return ret;
    }
    len += URI_PREFIX_FILE_LEN;

    spinlock_lock(&g_trusted_file_lock);

    LISTP_FOR_EACH_ENTRY(tmp, &g_trusted_file_list, list) {
        if (tmp->stubs) {
            /* trusted files: must be exactly the same URI */
            if (tmp->uri_len == len && !memcmp(tmp->uri, normpath, len + 1)) {
                tf = tmp;
                break;
            }
        } else {
            /* allowed files: must be a subfolder or file */
            if (path_is_equal_or_subpath(tmp, normpath, len)) {
                tf = tmp;
                break;
            }
        }
    }

    spinlock_unlock(&g_trusted_file_lock);

    if (!tf || tf->allowed) {
        if (!tf) {
            if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG)
                return -PAL_ERROR_DENIED;

            pal_printf("Allowing access to an unknown file due to "
                       "file_check_policy settings: %s\n", uri);
        }

        *stubptr = NULL;
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(normpath, &attr);
        if (!ret)
            *sizeptr = attr.pending_size;
        else
            *sizeptr = 0;

        return 0;
    }

    /* trusted file must be a regular file (seekable) */
    if (!file->file.seekable)
        return -PAL_ERROR_DENIED;

    sgx_stub_t* stubs = NULL;
    /* mmap the whole trusted file in untrusted memory for future reads/writes; it is
     * caller's responsibility to unmap those areas after use */
    *sizeptr = tf->size;
    if (*sizeptr) {
        ret = ocall_mmap_untrusted(umem, tf->size, PROT_READ, MAP_SHARED, fd, /*offset=*/0);
        if (IS_ERR(ret)) {
            *umem = NULL;
            ret = unix_to_pal_error(ERRNO(ret));
            goto failed;
        }
    }

    spinlock_lock(&g_trusted_file_lock);
    if (tf->stubs) {
        *stubptr = tf->stubs;
        spinlock_unlock(&g_trusted_file_lock);
        return 0;
    }
    spinlock_unlock(&g_trusted_file_lock);

    int nstubs = tf->size / TRUSTED_STUB_SIZE +
                (tf->size % TRUSTED_STUB_SIZE ? 1 : 0);

    stubs = malloc(sizeof(sgx_stub_t) * nstubs);
    if (!stubs) {
        ret = -PAL_ERROR_NOMEM;
        goto failed;
    }

    sgx_stub_t* s = stubs; /* stubs is an array of 128bit values */
    uint64_t offset = 0;
    LIB_SHA256_CONTEXT sha;

    ret = lib_SHA256Init(&sha);
    if (ret < 0)
        goto failed;

    for (; offset < tf->size; offset += TRUSTED_STUB_SIZE, s++) {
        /* For each stub, generate a 128bit hash of a file chunk with
         * AES-CMAC, and then update the SHA256 digest. */
        uint64_t mapping_size = MIN(tf->size - offset, TRUSTED_STUB_SIZE);
        LIB_AESCMAC_CONTEXT aes_cmac;
        ret = lib_AESCMACInit(&aes_cmac, (uint8_t*)&g_enclave_key, sizeof(g_enclave_key));
        if (ret < 0)
            goto failed;

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
            memcpy(small_chunk, *umem + offset + chunk_offset, chunk_size);

            /* Update the file checksum */
            ret = lib_SHA256Update(&sha, small_chunk, chunk_size);
            if (ret < 0)
                goto failed;

            /* Update the checksum for the file chunk */
            ret = lib_AESCMACUpdate(&aes_cmac, small_chunk, chunk_size);
            if (ret < 0)
                goto failed;
        }

        /* Store the checksum for one file chunk for checking */
        ret = lib_AESCMACFinish(&aes_cmac, (uint8_t*)s, sizeof(*s));
        if (ret < 0)
            goto failed;
    }

    sgx_checksum_t hash;

    /* Finalize and checking if the checksum of the whole file matches
     * with record given in the manifest. */

    ret = lib_SHA256Final(&sha, (uint8_t*)hash.bytes);
    if (ret < 0)
        goto failed;

    if (memcmp(&hash, &tf->checksum, sizeof(sgx_checksum_t))) {
        ret = -PAL_ERROR_DENIED;
        goto failed;
    }

    spinlock_lock(&g_trusted_file_lock);
    if (tf->stubs) {
        *stubptr = tf->stubs;
        spinlock_unlock(&g_trusted_file_lock);
        free(stubs);
        return 0;
    }
    *stubptr = tf->stubs = stubs;
    spinlock_unlock(&g_trusted_file_lock);
    return 0;

failed:
    if (*umem) {
        assert(*sizeptr > 0);
        ocall_munmap_untrusted(*umem, *sizeptr);
    }
    free(stubs);

    return ret;
}

int get_file_check_policy(void) {
    return g_file_check_policy;
}

static void set_file_check_policy(int policy) {
    g_file_check_policy = policy;
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
int copy_and_verify_trusted_file(const char* path, const void* umem, uint64_t umem_start,
                                 uint64_t umem_end, void* buffer, uint64_t offset, uint64_t size,
                                 sgx_stub_t* stubs, uint64_t total_size) {
    /* Check that the untrusted mapping is aligned to TRUSTED_STUB_SIZE
     * and includes the range for copying into the buffer */
    assert(IS_ALIGNED(umem_start, TRUSTED_STUB_SIZE));
    assert(offset >= umem_start && offset + size <= umem_end);

    /* Start copying and checking at umem_start. The checked content may or
     * may not be copied into the file content, depending on the offset of
     * the content within the file. */
    uint64_t checking = umem_start;
    /* The stubs is an array of 128-bit hash values of the file chunks.
     * from the beginning of the file. 's' points to the stub that needs to
     * be checked for the current offset. */
    sgx_stub_t* s = stubs + checking / TRUSTED_STUB_SIZE;
    int ret = 0;

    for (; checking < umem_end; checking += TRUSTED_STUB_SIZE, s++) {
        /* Check one chunk at a time. */
        uint64_t checking_size = MIN(total_size - checking, TRUSTED_STUB_SIZE);
        uint64_t checking_end = checking + checking_size;
        sgx_checksum_t hash;

        if (checking >= offset && checking_end <= offset + size) {
            /* If the checking chunk completely overlaps with the region
             * needed for copying into the buffer, simplying use the buffer
             * for checking */
            memcpy(buffer + checking - offset, umem + checking - umem_start, checking_size);

            /* Storing the checksum (using AES-CMAC) inside hash. */
            ret = lib_AESCMAC((uint8_t*)&g_enclave_key, sizeof(g_enclave_key),
                              buffer + checking - offset, checking_size, (uint8_t*)&hash,
                              sizeof(hash));
        } else {
            /* If the checking chunk only partially overlaps with the region,
             * read the file content in smaller chunks and only copy the part
             * needed by the caller. */
            LIB_AESCMAC_CONTEXT aes_cmac;
            ret = lib_AESCMACInit(&aes_cmac, (uint8_t*)&g_enclave_key, sizeof(g_enclave_key));
            if (ret < 0)
                goto failed;

            uint8_t small_chunk[FILE_CHUNK_SIZE]; /* A small buffer */
            uint64_t chunk_offset = checking;

            for (; chunk_offset < checking_end; chunk_offset += FILE_CHUNK_SIZE) {
                uint64_t chunk_size = MIN(checking_end - chunk_offset, FILE_CHUNK_SIZE);

                /* Copy into the small buffer before hashing the content */
                memcpy(small_chunk, umem + (chunk_offset - umem_start), chunk_size);

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
            SGX_DBG(DBG_E,
                    "Accesing file:%s is denied. Does not match with MAC at chunk starting at "
                    "%lu-%lu.\n",
                    path, checking, checking_end);
            return -PAL_ERROR_DENIED;
        }
    }

    return 0;

failed:
    return -PAL_ERROR_DENIED;
}

static int register_trusted_file(const char* uri, const char* checksum_str, bool check_duplicates) {
    int ret;

    size_t uri_len = strlen(uri);
    if (uri_len >= URI_MAX) {
        SGX_DBG(DBG_E, "Size of file exceeds maximum %dB: %s\n", URI_MAX, uri);
        return -PAL_ERROR_INVAL;
    }

    if (check_duplicates) {
        /* this check is only done during runtime (when creating a new file) and not needed during
         * initialization (because manifest is assumed to have no duplicates); skipping this check
         * significantly improves startup time */
        spinlock_lock(&g_trusted_file_lock);
        struct trusted_file* tf;
        LISTP_FOR_EACH_ENTRY(tf, &g_trusted_file_list, list) {
            if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
                spinlock_unlock(&g_trusted_file_lock);
                return 0;
            }
        }
        spinlock_unlock(&g_trusted_file_lock);
    }

    struct trusted_file* new = malloc(sizeof(*new) + uri_len + 1);
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    new->size    = 0;
    new->stubs   = NULL;
    new->allowed = false;
    new->uri_len = uri_len;
    memcpy(new->uri, uri, uri_len + 1);

    if (checksum_str) {
        PAL_STREAM_ATTR attr;
        ret = _DkStreamAttributesQuery(uri, &attr);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Could not find size of file: %s\n", uri);
            free(new);
            return ret;
        }
        new->size = attr.pending_size;

        assert(strlen(checksum_str) >= sizeof(sgx_checksum_t) * 2);
        for (size_t i = 0; i < sizeof(sgx_checksum_t); i++) {
            int8_t byte1 = hex2dec(checksum_str[i * 2]);
            int8_t byte2 = hex2dec(checksum_str[i * 2 + 1]);

            if (byte1 < 0 || byte2 < 0) {
                SGX_DBG(DBG_E, "Could not parse checksum of file: %s\n", uri);
                free(new);
                return -PAL_ERROR_INVAL;
            }

            new->checksum.bytes[i] = byte1 * 16 + byte2;
        }

        SGX_DBG(DBG_S, "trusted: %s\n", new->uri);
    } else {
        memset(&new->checksum, 0, sizeof(sgx_checksum_t));
        new->allowed = true;
        SGX_DBG(DBG_S, "allowed: %s\n", new->uri);
    }

    spinlock_lock(&g_trusted_file_lock);

    if (check_duplicates) {
        /* this check is only done during runtime and not needed during initialization (see above);
         * we check again because same file could have been added by another thread in meantime */
        struct trusted_file* tf;
        LISTP_FOR_EACH_ENTRY(tf, &g_trusted_file_list, list) {
            if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
                spinlock_unlock(&g_trusted_file_lock);
                free(new);
                return 0;
            }
        }
    }

    LISTP_ADD_TAIL(new, &g_trusted_file_list, list);
    spinlock_unlock(&g_trusted_file_lock);

    return 0;
}

static int init_trusted_file(const char* key, const char* uri) {
    int ret;

    /* read sgx.trusted_checksum.<key> entry from manifest */
    char* fullkey = alloc_concat("sgx.trusted_checksum.", static_strlen("sgx.trusted_checksum."),
                                 key, strlen(key));
    if (!fullkey)
        return -PAL_ERROR_NOMEM;

    char* trusted_checksum = NULL;
    ret = toml_string_in(g_pal_state.manifest_root, fullkey, &trusted_checksum);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'%s\' (the value must be put in double quotes!)\n", fullkey);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* Normalize the uri */
    char normpath[URI_MAX] = URI_PREFIX_FILE;
    if (!strstartswith(uri, URI_PREFIX_FILE)) {
        SGX_DBG(DBG_E, "Invalid URI [%s]: Trusted files must start with 'file:'\n", uri);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }
    size_t len = sizeof(normpath) - strlen(normpath);
    ret = get_norm_path(uri + URI_PREFIX_FILE_LEN, normpath + URI_PREFIX_FILE_LEN, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Path (%s) normalization failed: %s\n", uri + URI_PREFIX_FILE_LEN,
                pal_strerror(-ret));
        goto out;
    }

    ret = register_trusted_file(normpath, trusted_checksum, /*check_duplicates=*/false);
out:
    free(trusted_checksum);
    free(fullkey);
    return ret;
}

int init_trusted_files(void) {
    int ret;

    ret = init_trusted_file("exec", g_pal_sec.exec_name);
    if (ret < 0)
        return ret;

    /* read loader.preload string from manifest and register its files as trusted */
    char* preload_str = NULL;
    ret = toml_string_in(g_pal_state.manifest_root, "loader.preload", &preload_str);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'loader.preload\' "
                       "(the value must be put in double quotes!)\n");
        return -PAL_ERROR_INVAL;
    }

    if (preload_str) {
        int npreload = 0;
        char key[10];
        const char* start;
        const char* end;
        size_t len = strlen(preload_str);

        for (start = preload_str; start < preload_str + len; start = end + 1) {
            for (end = start; end < preload_str + len && *end && *end != ','; end++)
                ;
            if (end > start) {
                char uri[end - start + 1];
                memcpy(uri, start, end - start);
                uri[end - start] = 0;
                snprintf(key, 10, "preload%d", npreload++);

                ret = init_trusted_file(key, uri);
                if (ret < 0) {
                    free(preload_str);
                    return ret;
                }
            }
        }

        free(preload_str);
    }

    /* read sgx.trusted_files entries from manifest and register them */
    toml_table_t* manifest_sgx = toml_table_in(g_pal_state.manifest_root, "sgx");
    if (!manifest_sgx)
        goto no_trusted;

    toml_table_t* toml_trusted_files = toml_table_in(manifest_sgx, "trusted_files");
    if (!toml_trusted_files)
        goto no_trusted;

    ssize_t toml_trusted_files_cnt = toml_table_nkval(toml_trusted_files);
    if (toml_trusted_files_cnt <= 0)
        goto no_trusted;

    for (ssize_t i = 0; i < toml_trusted_files_cnt; i++) {
        const char* toml_trusted_file_key = toml_key_in(toml_trusted_files, i);
        assert(toml_trusted_file_key);
        toml_raw_t toml_trusted_file_raw = toml_raw_in(toml_trusted_files, toml_trusted_file_key);
        assert(toml_trusted_file_raw);

        char* toml_trusted_file_str = NULL;
        ret = toml_rtos(toml_trusted_file_raw, &toml_trusted_file_str);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Invalid trusted file in manifest: \'%s\'\n", toml_trusted_file_key);
            continue;
        }

        ret = init_trusted_file(toml_trusted_file_key, toml_trusted_file_str);
        if (ret < 0) {
            free(toml_trusted_file_str);
            return ret;
        }

        free(toml_trusted_file_str);
    }

no_trusted:
    /* read sgx.allowed_files entries from manifest and register them */
    if (!manifest_sgx)
        goto no_allowed;

    toml_table_t* toml_allowed_files = toml_table_in(manifest_sgx, "allowed_files");
    if (!toml_allowed_files)
        goto no_allowed;

    ssize_t toml_allowed_files_cnt = toml_table_nkval(toml_allowed_files);
    if (toml_allowed_files_cnt <= 0)
        goto no_allowed;

    for (ssize_t i = 0; i < toml_allowed_files_cnt; i++) {
        const char* toml_allowed_file_key = toml_key_in(toml_allowed_files, i);
        assert(toml_allowed_file_key);
        toml_raw_t toml_allowed_file_raw = toml_raw_in(toml_allowed_files, toml_allowed_file_key);
        assert(toml_allowed_file_raw);

        char* toml_allowed_file_str = NULL;
        ret = toml_rtos(toml_allowed_file_raw, &toml_allowed_file_str);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Invalid allowed file in manifest: \'%s\'\n", toml_allowed_file_key);
            continue;
        }

        char norm_path[URI_MAX];

        if (!strstartswith(toml_allowed_file_str, URI_PREFIX_FILE)) {
            SGX_DBG(DBG_E, "Invalid URI [%s]: Allowed files must start with 'file:'\n",
                    toml_allowed_file_str);
            free(toml_allowed_file_str);
            return -PAL_ERROR_INVAL;
        }
        static_assert(sizeof(norm_path) > URI_PREFIX_FILE_LEN, "`normpath` is too small");
        memcpy(norm_path, URI_PREFIX_FILE, URI_PREFIX_FILE_LEN);

        size_t norm_path_len = sizeof(norm_path) - URI_PREFIX_FILE_LEN;

        ret = get_norm_path(toml_allowed_file_str + URI_PREFIX_FILE_LEN,
                            norm_path + URI_PREFIX_FILE_LEN, &norm_path_len);
        free(toml_allowed_file_str);

        if (ret < 0) {
            SGX_DBG(DBG_E, "Path (%s) normalization failed: %s\n",
                    toml_allowed_file_str + URI_PREFIX_FILE_LEN, pal_strerror(-ret));
            return ret;
        }

        register_trusted_file(norm_path, NULL, /*check_duplicates=*/false);
    }

no_allowed:
    return 0;
}

int init_trusted_children(void) {
    int ret;

    /* read sgx.trusted_children and corresponding sgx.trusted_mrenclave entries from manifest */
    toml_table_t* manifest_sgx = toml_table_in(g_pal_state.manifest_root, "sgx");
    if (!manifest_sgx)
        return 0;

    toml_table_t* toml_trusted_children = toml_table_in(manifest_sgx, "trusted_children");
    if (!toml_trusted_children)
        return 0;

    ssize_t toml_trusted_children_cnt = toml_table_nkval(toml_trusted_children);
    if (toml_trusted_children_cnt <= 0)
        return 0;

    toml_table_t* toml_trusted_mrenclaves = toml_table_in(manifest_sgx, "trusted_mrenclave");
    if (!toml_trusted_mrenclaves) {
        SGX_DBG(DBG_E, "No corresponding \'sgx.trusted_mrenclave\' to \'sgx.trusted_children\'\n");
        return -PAL_ERROR_INVAL;
    }

    ssize_t toml_trusted_mrenclaves_cnt = toml_table_nkval(toml_trusted_mrenclaves);
    if (toml_trusted_mrenclaves_cnt != toml_trusted_children_cnt) {
        SGX_DBG(DBG_E, "No corresponding \'sgx.trusted_mrenclave\' to \'sgx.trusted_children\'\n");
        return -PAL_ERROR_INVAL;
    }

    for (ssize_t i = 0; i < toml_trusted_mrenclaves_cnt; i++) {
        const char* toml_trusted_mrenclave_key = toml_key_in(toml_trusted_mrenclaves, i);
        assert(toml_trusted_mrenclave_key);
        toml_raw_t toml_trusted_mrenclave_raw = toml_raw_in(toml_trusted_mrenclaves,
                                                            toml_trusted_mrenclave_key);
        assert(toml_trusted_mrenclave_raw);

        /* find corresponding trusted_children from trusted_mrenclave */
        toml_raw_t toml_trusted_child_raw = toml_raw_in(toml_trusted_children,
                                                        toml_trusted_mrenclave_key);
        if (!toml_trusted_child_raw) {
            SGX_DBG(DBG_E, "No \'sgx.trusted_children.%s\' found\n", toml_trusted_mrenclave_key);
            return -PAL_ERROR_INVAL;
        }

        char* toml_trusted_mrenclave_str = NULL;
        ret = toml_rtos(toml_trusted_mrenclave_raw, &toml_trusted_mrenclave_str);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Invalid trusted mrenclave in manifest: \'%s\'\n",
                    toml_trusted_mrenclave_key);
            return -PAL_ERROR_INVAL;
        }

        char* toml_trusted_child_str = NULL;
        ret = toml_rtos(toml_trusted_child_raw, &toml_trusted_child_str);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Invalid trusted child in manifest: \'%s\'\n",
                    toml_trusted_mrenclave_key);
            free(toml_trusted_mrenclave_str);
            return -PAL_ERROR_INVAL;
        }

        ret = register_trusted_child(toml_trusted_child_str, toml_trusted_mrenclave_str);
        free(toml_trusted_mrenclave_str);
        free(toml_trusted_child_str);

        if (ret < 0)
            return ret;
    }

    return 0;
}

int init_file_check_policy(void) {
    int ret;

    char* file_check_policy_str = NULL;
    ret = toml_string_in(g_pal_state.manifest_root, "sgx.file_check_policy",
                         &file_check_policy_str);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Cannot parse \'sgx.file_check_policy\' "
                       "(the value must be put in double quotes!)\n");
        return -PAL_ERROR_INVAL;
    }

    if (!file_check_policy_str)
        return 0;

    if (!strcmp(file_check_policy_str, "strict")) {
        set_file_check_policy(FILE_CHECK_POLICY_STRICT);
    } else if (!strcmp(file_check_policy_str, "allow_all_but_log")) {
        set_file_check_policy(FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG);
    } else {
        SGX_DBG(DBG_E, "Unknown value for \'sgx.file_check_policy\' "
                "(allowed: `strict`, `allow_all_but_log`)'\n");
        free(file_check_policy_str);
        return -PAL_ERROR_INVAL;
    }

    SGX_DBG(DBG_S, "File check policy: %s\n", file_check_policy_str);
    free(file_check_policy_str);
    return 0;
}

int init_enclave(void) {
    // Get report to initialize info (MR_ENCLAVE, etc.) about this enclave from
    // a trusted source.

    // Since this report is only read by ourselves we can
    // leave targetinfo zeroed.
    __sgx_mem_aligned sgx_target_info_t targetinfo = {0};
    __sgx_mem_aligned struct pal_enclave_state reportdata = {0};
    __sgx_mem_aligned sgx_report_t report;

    static_assert(sizeof(reportdata) == sizeof(sgx_report_data_t),
                  "incompatible `reportdata` size");
    int ret = sgx_report(&targetinfo, &reportdata, &report);
    if (ret) {
        SGX_DBG(DBG_E, "failed to get self report: %d\n", ret);
        return -PAL_ERROR_INVAL;
    }

    memcpy(&g_pal_sec.mr_enclave, &report.body.mr_enclave, sizeof(g_pal_sec.mr_enclave));
    memcpy(&g_pal_sec.mr_signer, &report.body.mr_signer, sizeof(g_pal_sec.mr_signer));
    g_pal_sec.enclave_attributes = report.body.attributes;

    /*
     * The enclave id is uniquely created for each enclave as a token
     * for authenticating the enclave as the sender of attestation.
     * See 'host/Linux-SGX/db_process.c' for further explanation.
     */
    ret = _DkRandomBitsRead(&g_pal_enclave_state.enclave_id,
                            sizeof(g_pal_enclave_state.enclave_id));
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to generate a random id: %d\n", ret);
        return ret;
    }

    return 0;
}

int _DkStreamKeyExchange(PAL_HANDLE stream, PAL_SESSION_KEY* key) {
    uint8_t pub[DH_SIZE]   __attribute__((aligned(DH_SIZE)));
    uint8_t agree[DH_SIZE] __attribute__((aligned(DH_SIZE)));
    PAL_NUM pubsz, agreesz;
    LIB_DH_CONTEXT context;
    int64_t bytes;
    int64_t ret;

    ret = lib_DhInit(&context);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH Init failed: %ld\n", ret);
        goto out_no_final;
    }

    pubsz = sizeof pub;
    ret = lib_DhCreatePublic(&context, pub, &pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH CreatePublic failed: %ld\n", ret);
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

    for (bytes = 0, ret = 0; bytes < DH_SIZE; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, DH_SIZE - bytes, pub + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to exchange the secret key via RPC: %ld\n", ret);
            goto out;
        }
    }

    for (bytes = 0, ret = 0; bytes < DH_SIZE; bytes += ret) {
        ret = _DkStreamRead(stream, 0, DH_SIZE - bytes, pub + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to exchange the secret key via RPC: %ld\n", ret);
            goto out;
        }
    }

    agreesz = sizeof agree;
    ret = lib_DhCalcSecret(&context, pub, DH_SIZE, agree, &agreesz);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Key Exchange: DH CalcSecret failed: %ld\n", ret);
        goto out;
    }

    assert(agreesz > 0 && agreesz <= sizeof agree);

    /*
     * Using SHA256 as a KDF to convert the 128-byte DH secret to a 256-bit AES key.
     * According to the NIST recommendation:
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf,
     * a key derivation function (KDF) can be a secure hash function (e.g., SHA-256),
     * HMAC, or KMAC.
     */
    LIB_SHA256_CONTEXT sha;
    if ((ret = lib_SHA256Init(&sha)) < 0 ||
        (ret = lib_SHA256Update(&sha, agree, agreesz)) < 0 ||
        (ret = lib_SHA256Final(&sha, (uint8_t*)key)) < 0) {
        SGX_DBG(DBG_E, "Failed to derive the session key: %ld\n", ret);
        goto out;
    }

    SGX_DBG(DBG_S, "Key exchange succeeded: %s\n", ALLOCA_BYTES2HEXSTR(*key));
    ret = 0;
out:
    lib_DhFinal(&context);
out_no_final:
    return ret;
}

/*
 * Initalize the request of local report exchange.
 *
 * We refer to this enclave as A and to the other enclave as B, e.g., A is this
 * parent enclave and B is the child enclave in the fork case (for more info,
 * see comments in db_process.c).
 */
int _DkStreamReportRequest(PAL_HANDLE stream, sgx_sign_data_t* data,
                           check_mr_enclave_t check_mr_enclave) {
    __sgx_mem_aligned sgx_target_info_t target_info;
    __sgx_mem_aligned sgx_report_t report;
    uint64_t bytes;
    int64_t ret;

    /* A -> B: targetinfo[A] */
    memset(&target_info, 0, sizeof(target_info));
    memcpy(&target_info.mr_enclave, &g_pal_sec.mr_enclave, sizeof(sgx_measurement_t));
    memcpy(&target_info.attributes, &g_pal_sec.enclave_attributes, sizeof(sgx_attributes_t));

    for (bytes = 0, ret = 0; bytes < SGX_TARGETINFO_FILLED_SIZE; bytes += ret) {
        ret = _DkStreamWrite(stream, 0, SGX_TARGETINFO_FILLED_SIZE - bytes,
                             ((void*)&target_info) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to send target info via RPC: %ld\n", ret);
            goto out;
        }
    }

    /* B -> A: report[B -> A] */
    for (bytes = 0, ret = 0; bytes < sizeof(report); bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(report) - bytes, ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to receive local report via RPC: %ld\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received local report (mr_enclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(report.body.mr_enclave.m));

    /* Verify report[B -> A] */
    ret = sgx_verify_report(&report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to verify local report: %ld\n", ret);
        goto out;
    }

    struct pal_enclave_state* remote_state = (void*)&report.body.report_data;
    ret = check_mr_enclave(stream, &report.body.mr_enclave, remote_state);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to check local report: %ld\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E,
                "Not an allowed enclave (mr_enclave = %s). Maybe missing 'sgx.trusted_children' in "
                "the manifest file?\n",
                ALLOCA_BYTES2HEXSTR(report.body.mr_enclave.m));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Local attestation succeeded!\n");

    /* A -> B: report[A -> B] */
    memcpy(&target_info.mr_enclave, &report.body.mr_enclave, sizeof(sgx_measurement_t));
    memcpy(&target_info.attributes, &report.body.attributes, sizeof(sgx_attributes_t));

    ret = __sgx_get_report(&target_info, data, &report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get local report from CPU: %ld\n", ret);
        goto out;
    }

    for (bytes = 0, ret = 0; bytes < sizeof(report); bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(report) - bytes, ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to send local report via RPC: %ld\n", ret);
            goto out;
        }
    }

    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

/*
 * Respond to the request of local report exchange.
 *
 * We refer to this enclave as B and to the other enclave as A, e.g., B is this
 * child enclave and A is the parent enclave in the fork case (for more info,
 * see comments in db_process.c).
 */
int _DkStreamReportRespond(PAL_HANDLE stream, sgx_sign_data_t* data,
                           check_mr_enclave_t check_mr_enclave) {
    __sgx_mem_aligned sgx_target_info_t target_info;
    __sgx_mem_aligned sgx_report_t report;
    uint64_t bytes;
    int64_t ret;
    memset(&target_info, 0, sizeof(target_info));

    /* A -> B: targetinfo[A] */
    for (bytes = 0, ret = 0; bytes < SGX_TARGETINFO_FILLED_SIZE; bytes += ret) {
        ret = _DkStreamRead(stream, 0, SGX_TARGETINFO_FILLED_SIZE - bytes,
                            ((void*)&target_info) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to receive target info via RPC: %ld\n", ret);
            goto out;
        }
    }

    /* B -> A: report[B -> A] */
    ret = __sgx_get_report(&target_info, data, &report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get local report from CPU: %ld\n", ret);
        goto out;
    }

    for (bytes = 0, ret = 0; bytes < sizeof(report); bytes += ret) {
        ret = _DkStreamWrite(stream, 0, sizeof(report) - bytes, ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to send local report via PRC: %ld\n", ret);
            goto out;
        }
    }

    /* A -> B: report[A -> B] */
    for (bytes = 0, ret = 0; bytes < sizeof(report); bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(report) - bytes, ((void*)&report) + bytes, NULL, 0);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                ret = 0;
                continue;
            }
            SGX_DBG(DBG_E, "Failed to receive local report via RPC: %ld\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received local report (mr_enclave = %s)\n",
            ALLOCA_BYTES2HEXSTR(report.body.mr_enclave.m));

    /* Verify report[A -> B] */
    ret = sgx_verify_report(&report);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to verify local report: %ld\n", ret);
        goto out;
    }

    struct pal_enclave_state* remote_state = (void*)&report.body.report_data;
    ret = check_mr_enclave(stream, &report.body.mr_enclave, remote_state);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to check mr_enclave: %ld\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_E,
                "Not an allowed enclave (mr_enclave = %s). Maybe missing 'sgx.trusted_children' in "
                "the manifest file?\n",
                ALLOCA_BYTES2HEXSTR(report.body.mr_enclave.m));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Local attestation succeeded!\n");
    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}

int _DkStreamSecureInit(PAL_HANDLE stream, bool is_server, PAL_SESSION_KEY* session_key,
                        LIB_SSL_CONTEXT** out_ssl_ctx, const uint8_t* buf_load_ssl_ctx,
                        size_t buf_size) {
    int stream_fd;

    if (IS_HANDLE_TYPE(stream, process))
        stream_fd = stream->process.stream;
    else if (IS_HANDLE_TYPE(stream, pipe) || IS_HANDLE_TYPE(stream, pipecli))
        stream_fd = stream->pipe.fd;
    else
        return -PAL_ERROR_BADHANDLE;

    LIB_SSL_CONTEXT* ssl_ctx = malloc(sizeof(*ssl_ctx));
    if (!ssl_ctx)
        return -PAL_ERROR_NOMEM;

    /* mbedTLS init routines are not thread safe, so we use a spinlock to protect them */
    static spinlock_t ssl_init_lock = INIT_SPINLOCK_UNLOCKED;

    spinlock_lock(&ssl_init_lock);
    int ret = lib_SSLInit(ssl_ctx, stream_fd, is_server,
                          (const uint8_t*)session_key, sizeof(*session_key),
                          ocall_read, ocall_write, buf_load_ssl_ctx, buf_size);
    spinlock_unlock(&ssl_init_lock);

    if (ret != 0) {
        free(ssl_ctx);
        return ret;
    }

    if (!buf_load_ssl_ctx) {
        /* TLS context was not restored from the buffer, need to perform handshake */
        ret = lib_SSLHandshake(ssl_ctx);
        if (ret != 0) {
            free(ssl_ctx);
            return ret;
        }
    }

    *out_ssl_ctx = ssl_ctx;
    return 0;
}

int _DkStreamSecureFree(LIB_SSL_CONTEXT* ssl_ctx) {
    lib_SSLFree(ssl_ctx);
    free(ssl_ctx);
    return 0;
}

int _DkStreamSecureRead(LIB_SSL_CONTEXT* ssl_ctx, uint8_t* buf, size_t len) {
    return lib_SSLRead(ssl_ctx, buf, len);
}

int _DkStreamSecureWrite(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t* buf, size_t len) {
    return lib_SSLWrite(ssl_ctx, buf, len);
}

int _DkStreamSecureSave(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t** obuf, size_t* olen) {
    assert(obuf);
    assert(olen);

    int ret;

    /* figure out the required buffer size */
    ret = lib_SSLSave(ssl_ctx, NULL, 0, olen);
    if (ret != 0 && ret != -PAL_ERROR_NOMEM)
        return ret;

    /* create the required buffer */
    size_t len   = *olen;
    uint8_t* buf = malloc(len);
    if (!buf)
        return -PAL_ERROR_NOMEM;

    /* now have buffer with sufficient size to save serialized context */
    ret = lib_SSLSave(ssl_ctx, buf, len, olen);
    if (ret != 0 || len != *olen) {
        free(buf);
        return -PAL_ERROR_DENIED;
    }

    *obuf = buf;
    return 0;
}
