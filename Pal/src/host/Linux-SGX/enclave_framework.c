/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <api.h>
#include <linux_list.h>

#include "enclave_pages.h"

struct pal_enclave_state pal_enclave_state;
struct pal_enclave pal_enclave;

bool sgx_is_within_enclave (const void * addr, uint64_t size)
{
    return addr >= pal_enclave.enclave_base &&
           addr + size <= pal_enclave.enclave_base + pal_enclave.enclave_size;
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
    SGX_DBG(DBG_S, "    cpusvn:           %08x %08x\n", report->cpusvn[0],
                                                report->cpusvn[1]);
    SGX_DBG(DBG_S, "    mrenclave:        %s\n",        hex2str(report->mrenclave));
    SGX_DBG(DBG_S, "    mrsigner:         %s\n",        hex2str(report->mrsigner));
    SGX_DBG(DBG_S, "    attributes.flags: %016lx\n",    report->attributes.flags);
    SGX_DBG(DBG_S, "    sttributes.xfrm:  %016lx\n",    report->attributes.xfrm);

    SGX_DBG(DBG_S, "    isvprodid:        %02x\n",      report->isvprodid);
    SGX_DBG(DBG_S, "    isvsvn:           %02x\n",      report->isvsvn);
    SGX_DBG(DBG_S, "    keyid:            %s\n",        hex2str(report->keyid));
    SGX_DBG(DBG_S, "    mac:              %s\n",        hex2str(report->mac));

    return 0;
}

#include "crypto/cmac.h"

static sgx_arch_key128_t enclave_key;

int sgx_verify_report (sgx_arch_report_t * report)
{
    sgx_arch_keyrequest_t keyrequest;
    memset(&keyrequest, 0, sizeof(sgx_arch_keyrequest_t));
    keyrequest.keyname = REPORT_KEY;
    memcpy(keyrequest.keyid, report->keyid, sizeof(keyrequest.keyid));

    int ret = sgx_getkey(&keyrequest, &enclave_key);
    if (ret) {
        SGX_DBG(DBG_S, "Can't get report key\n");
        return -PAL_ERROR_DENIED;
    }

    SGX_DBG(DBG_S, "Get report key for verification: %s\n", hex2str(enclave_key));
    return 0;
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

    SGX_DBG(DBG_S, "Get sealing key: %s\n", hex2str(enclave_key));
    return 0;
}

struct trusted_file {
    struct list_head list;
    int64_t         index;
    uint64_t        size;
    int             uri_len;
    char            uri[URI_MAX];
    sgx_checksum_t  checksum;
    sgx_stub_t *    stubs;
};

static LIST_HEAD(trusted_file_list);
static struct spinlock trusted_file_lock = LOCK_INIT;
static int trusted_file_indexes = 0;

#include <crypto/sha256.h>
#include <crypto/sha512.h>

int load_trusted_file (PAL_HANDLE file, sgx_stub_t ** stubptr,
                       uint64_t * sizeptr)
{
    struct trusted_file * tf = NULL, * tmp;
    char uri[URI_MAX];
    int ret, fd = HANDLE_HDR(file)->fds[0], uri_len;

    if (!(HANDLE_HDR(file)->flags & RFD(0))) 
        return -PAL_ERROR_DENIED;

    uri_len = _DkStreamGetName(file, uri, URI_MAX);
    if (uri_len < 0)
        return uri_len;

    _DkSpinLock(&trusted_file_lock);

    list_for_each_entry(tmp, &trusted_file_list, list)
        if (tmp->stubs) {
            /* trusted files: must be exactly the same URI */
            if (tmp->uri_len == uri_len && !memcmp(tmp->uri, uri, uri_len + 1)) {
                tf = tmp;
                break;
            }
        } else {
            /* allowed files: must be a subfolder or file */
            if (tmp->uri_len <= uri_len &&
                !memcmp(tmp->uri, uri, tmp->uri_len) &&
                (!uri[tmp->uri_len] || uri[tmp->uri_len] == '/')) {
                tf = tmp;
                break;
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
        ret = _DkStreamAttributesQuery(uri, &attr);
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

    sgx_stub_t * s = stubs;
    uint64_t offset = 0;
    SHA256 sha;
    void * umem;
    uint8_t hash[512/8];

    ret = SHA256Init(&sha);
    if (ret < 0)
        goto failed;

    if (!tf->size)
        goto done_hash;
    
    ret = ocall_map_untrusted(fd, 0, tf->size, PROT_READ, &umem);
    if (ret < 0)
        goto failed;

    for (; offset < tf->size; offset += TRUSTED_STUB_SIZE, s++) {
        uint64_t mapping_size = tf->size - offset;
        if (mapping_size > TRUSTED_STUB_SIZE)
            mapping_size = TRUSTED_STUB_SIZE;

        SHA512Hash(umem + offset, mapping_size, hash);
        memcpy(s, hash, sizeof(sgx_stub_t));

        /* update the file checksum */
        ret = SHA256Update(&sha, umem + offset, mapping_size);
    }

    ocall_unmap_untrusted(umem, tf->size);

done_hash:
    ret = SHA256Final(&sha, (uint8_t *) hash);
    if (ret < 0)
        goto failed;

    if (memcmp(hash, &tf->checksum, sizeof(sgx_checksum_t))) {
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
        if (!_DkStreamOpen(&handle, uri, PAL_ACCESS_RDONLY, 0, 0, 0))
            load_trusted_file (handle, &loaded_stub, &loaded_size);
    }
#endif

    return ret;
}

int verify_trusted_file (const char * uri, void * mem,
                         unsigned int offset, unsigned int size,
                         sgx_stub_t * stubs,
                         unsigned int total_size)
{
    unsigned long checking = offset;
    sgx_stub_t * s = stubs + checking / TRUSTED_STUB_SIZE;
    int ret;

    for (; checking < offset + size ; checking += TRUSTED_STUB_SIZE, s++) {
        unsigned long checking_size = TRUSTED_STUB_SIZE;
        if (checking_size > total_size - checking)
            checking_size = total_size - checking;

        uint8_t hash[512/8];
        SHA512Hash(mem + checking - offset, checking_size, hash);

        if (memcmp(s, hash, sizeof(sgx_stub_t))) {
            SGX_DBG(DBG_E, "Accesing file:%s is denied. "
                    "Does not match with its MAC.\n", uri);
            return -PAL_ERROR_DENIED;
        }
    }

    return 0;
}

static int register_trusted_file (const char * uri, const char * checksum_str)
{
    struct trusted_file * tf = NULL, * new;
    int uri_len = strlen(uri);
    int ret;

    _DkSpinLock(&trusted_file_lock);

    list_for_each_entry(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            return 0;
        }
    }
    _DkSpinUnlock(&trusted_file_lock);

    new = malloc(sizeof(struct trusted_file));
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(&new->list);
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

    list_for_each_entry(tf, &trusted_file_list, list) {
        if (tf->uri_len == uri_len && !memcmp(tf->uri, uri, uri_len)) {
            _DkSpinUnlock(&trusted_file_lock);
            free(new);
            return 0;
        }
    }

    list_add_tail(&new->list, &trusted_file_list);
    _DkSpinUnlock(&trusted_file_lock);
    return 0;
}

static int init_trusted_file (const char * key, const char * uri)
{
    char cskey[URI_MAX], * tmp;
    char checksum[URI_MAX];

    tmp = strcpy_static(cskey, "sgx.trusted_checksum.", URI_MAX);
    memcpy(tmp, key, strlen(key) + 1);

    int len = get_config(pal_state.root_config, cskey, checksum, CONFIG_MAX);
    if (len < 0)
        return 0;

    return register_trusted_file(uri, checksum);
}

int init_trusted_files (void)
{
    char cfgbuf[CONFIG_MAX];
    int ret;

    if (pal_sec.exec_fd != PAL_IDX_POISON) {
        ret = init_trusted_file("exec", pal_sec.exec_name);
        if (ret < 0)
            return ret;
    }

    int len = get_config(pal_state.root_config, "loader.preload",
                         cfgbuf, CONFIG_MAX);
    if (len) {
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
                    return ret;
            }
        }
    }

    int nuris = get_config_entries(pal_state.root_config, "sgx.trusted_files",
                                   cfgbuf, CONFIG_MAX);
    if (nuris) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.trusted_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0) {
                ret = init_trusted_file(key + 18, uri);
                if (ret < 0)
                    return ret;
            }
        }
    }

    nuris = get_config_entries(pal_state.root_config, "sgx.allowed_files",
                               cfgbuf, CONFIG_MAX);
    if (nuris > 0) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char * k = cfgbuf, * tmp;

        tmp = strcpy_static(key, "sgx.allowed_files.", CONFIG_MAX);

        for (int i = 0 ; i < nuris ; i++) {
            len = strlen(k);
            memcpy(tmp, k, len + 1);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0)
                register_trusted_file(uri, NULL);
        }
    }

    
    return 0;
}

int init_trusted_children (void)
{
    char cfgbuf[CONFIG_MAX];
    char key[CONFIG_MAX], mrkey[CONFIG_MAX];
    char uri[CONFIG_MAX], mrenclave[CONFIG_MAX];

    char * tmp1 = strcpy_static(key, "sgx.trusted_children.", CONFIG_MAX);
    char * tmp2 = strcpy_static(mrkey, "sgx.trusted_mrenclave.", CONFIG_MAX);

    int nuris = get_config_entries(pal_state.root_config,
                                   "sgx.trusted_mrenclave", cfgbuf, CONFIG_MAX);
    if (nuris > 0) {
        char * k = cfgbuf;
        for (int i = 0 ; i < nuris ; i++) {
            int len = strlen(k);
            memcpy(tmp1, k, len + 1);
            memcpy(tmp2, k, len + 1);
            k += len + 1;

            int ret = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (ret < 0)
                continue;

            ret = get_config(pal_state.root_config, mrkey, mrenclave,
                             CONFIG_MAX);
            if (ret > 0)
                register_trusted_child(uri, mrenclave);
        }
    }

    return 0;
}

#include "crypto/dh.h"

static struct {
    uint8_t p[128], q[20], g[128];
} dh_param = {
    {
        0xfd, 0x7f, 0x53, 0x81, 0x1d, 0x75, 0x12, 0x29,
        0x52, 0xdf, 0x4a, 0x9c, 0x2e, 0xec, 0xe4, 0xe7,
        0xf6, 0x11, 0xb7, 0x52, 0x3c, 0xef, 0x44, 0x00,
        0xc3, 0x1e, 0x3f, 0x80, 0xb6, 0x51, 0x26, 0x69,
        0x45, 0x5d, 0x40, 0x22, 0x51, 0xfb, 0x59, 0x3d,
        0x8d, 0x58, 0xfa, 0xbf, 0xc5, 0xf5, 0xba, 0x30,
        0xf6, 0xcb, 0x9b, 0x55, 0x6c, 0xd7, 0x81, 0x3b,
        0x80, 0x1d, 0x34, 0x6f, 0xf2, 0x66, 0x60, 0xb7,
        0x6b, 0x99, 0x50, 0xa5, 0xa4, 0x9f, 0x9f, 0xe8,
        0x04, 0x7b, 0x10, 0x22, 0xc2, 0x4f, 0xbb, 0xa9,
        0xd7, 0xfe, 0xb7, 0xc6, 0x1b, 0xf8, 0x3b, 0x57,
        0xe7, 0xc6, 0xa8, 0xa6, 0x15, 0x0f, 0x04, 0xfb,
        0x83, 0xf6, 0xd3, 0xc5, 0x1e, 0xc3, 0x02, 0x35,
        0x54, 0x13, 0x5a, 0x16, 0x91, 0x32, 0xf6, 0x75,
        0xf3, 0xae, 0x2b, 0x61, 0xd7, 0x2a, 0xef, 0xf2,
        0x22, 0x03, 0x19, 0x9d, 0xd1, 0x48, 0x01, 0xc7,
    },

    {
        0x97, 0x60, 0x50, 0x8f, 0x15, 0x23, 0x0b, 0xcc,
        0xb2, 0x92, 0xb9, 0x82, 0xa2, 0xeb, 0x84, 0x0b,
        0xf0, 0x58, 0x1c, 0xf5,
    },

    {
        0xf7, 0xe1, 0xa0, 0x85, 0xd6, 0x9b, 0x3d, 0xde,
        0xcb, 0xbc, 0xab, 0x5c, 0x36, 0xb8, 0x57, 0xb9,
        0x79, 0x94, 0xaf, 0xbb, 0xfa, 0x3a, 0xea, 0x82,
        0xf9, 0x57, 0x4c, 0x0b, 0x3d, 0x07, 0x82, 0x67,
        0x51, 0x59, 0x57, 0x8e, 0xba, 0xd4, 0x59, 0x4f,
        0xe6, 0x71, 0x07, 0x10, 0x81, 0x80, 0xb4, 0x49,
        0x16, 0x71, 0x23, 0xe8, 0x4c, 0x28, 0x16, 0x13,
        0xb7, 0xcf, 0x09, 0x32, 0x8c, 0xc8, 0xa6, 0xe1,
        0x3c, 0x16, 0x7a, 0x8b, 0x54, 0x7c, 0x8d, 0x28,
        0xe0, 0xa3, 0xae, 0x1e, 0x2b, 0xb3, 0xa6, 0x75,
        0x91, 0x6e, 0xa3, 0x7f, 0x0b, 0xfa, 0x21, 0x35,
        0x62, 0xf1, 0xfb, 0x62, 0x7a, 0x01, 0x24, 0x3b,
        0xcc, 0xa4, 0xf1, 0xbe, 0xa8, 0x51, 0x90, 0x89,
        0xa8, 0x83, 0xdf, 0xe1, 0x5a, 0xe5, 0x9f, 0x06,
        0x92, 0x8b, 0x66, 0x5e, 0x80, 0x7b, 0x55, 0x25,
        0x64, 0x01, 0x4c, 0x3b, 0xfe, 0xcf, 0x49, 0x2a,
    },
};

void test_dh (void)
{
    int ret;
    DhKey key1, key2;
    uint32_t privsz1, privsz2, pubsz1, pubsz2, agreesz1, agreesz2;
    unsigned char priv1[128], pub1[128], priv2[128], pub2[128], agree1[128],
                  agree2[128];

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

    SGX_DBG(DBG_S, "key exchange(side A): %s (%d)\n", __hex2str(agree1, agreesz1),
           agreesz1);
    SGX_DBG(DBG_S, "key exchange(side B): %s (%d)\n", __hex2str(agree2, agreesz2),
           agreesz2);
}

#include "crypto/rsa.h"

#define RSA_KEY_SIZE        2048
#define RSA_E               3

int init_enclave (void)
{
    int ret;
    RSAKey *rsa = malloc(sizeof(RSAKey));
    InitRSAKey(rsa);

    ret = MakeRSAKey(rsa, RSA_KEY_SIZE, RSA_E);
    if (ret < 0) {
        SGX_DBG(DBG_S, "MakeRSAKey failed: %d\n", ret);
        return ret;
    }

    uint32_t nsz = RSA_KEY_SIZE / 8, esz = 1;
    uint8_t n[nsz], e[esz];

    ret = RSAFlattenPublicKey(rsa, e, &esz, n, &nsz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "RSAFlattenPublicKey failed: %d\n", ret);
        goto out_free;
    }

    SHA512 sha512;
    uint8_t hash[512/8];

    ret = SHA512Init(&sha512);
    if (ret < 0)
        goto out_free;

    ret = SHA512Update(&sha512, n, nsz);
    if (ret < 0)
        goto out_free;

    ret = SHA512Final(&sha512, hash);
    if (ret < 0)
        goto out_free;

    memcpy(&pal_enclave_state.enclave_keyhash, hash,
           sizeof(sgx_checksum_t));

    pal_enclave.enclave_key = rsa;

    SGX_DBG(DBG_S, "enclave (software) key hash: %s\n",
           hex2str(pal_enclave_state.enclave_keyhash));

    return 0;

out_free:
    FreeRSAKey(rsa);
    free(rsa);
    return ret;
}

int _DkStreamKeyExchange (PAL_HANDLE stream, PAL_SESSION_KEY * keyptr)
{
    unsigned char session_key[32] __attribute__((aligned(32)));
    unsigned char priv[128]  __attribute__((aligned(128))),
                  pub[128]   __attribute__((aligned(128))),
                  agree[128] __attribute__((aligned(128)));
    uint32_t privsz, pubsz, agreesz;
    DhKey dh;
    int ret;

    InitDhKey(&dh);

    ret = DhSetKey(&dh, dh_param.p, sizeof(dh_param.p), dh_param.g,
                   sizeof(dh_param.g));
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DhSetKey failed: %d\n", ret);
        goto out;
    }

    ret = DhGenerateKeyPair(&dh, priv, &privsz, pub, &pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DhGenerateKeyPair failed: %d\n", ret);
        goto out;
    }

    ret = _DkStreamWrite(stream, 0, pubsz, pub, NULL, 0);
    if (ret < pubsz) {
        SGX_DBG(DBG_S, "Key Exchange: DkStreamWrite failed: %d\n", ret);
        goto out;
    }

    ret = _DkStreamRead(stream, 0, pubsz, pub, NULL, 0);
    if (ret < pubsz) {
        SGX_DBG(DBG_S, "Key Exchange: DkStreamRead failed: %d\n", ret);
        goto out;
    }

    ret = DhAgree(&dh, agree, &agreesz, priv, privsz, pub, pubsz);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Key Exchange: DhAgree failed: %d\n", ret);
        goto out;
    }

    memset(session_key, 0, sizeof(session_key));
    for (int i = 0 ; i < agreesz ; i++)
        session_key[i % sizeof(session_key)] ^= agree[i];

    SGX_DBG(DBG_S, "key exchange: (%p) %s\n", session_key, hex2str(session_key));

    if (keyptr)
        memcpy(keyptr, session_key, sizeof(PAL_SESSION_KEY));

    ret = 0;
out:
    FreeDhKey(&dh);
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
    int bytes, ret;

    memcpy(req.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&req.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation request ... (mrenclave = %s)\n",\
            hex2str(req.mrenclave));

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
            hex2str(att.mrenclave));

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

    ret = check_mrenclave(&att.report.mrenclave, &att.report.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check_mrenclave failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed encalve (mrenclave = %s)\n",
               hex2str(att.mrenclave));
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
            hex2str(att.mrenclave));

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
    int bytes, ret;

    for (bytes = 0, ret = 0 ; bytes < sizeof(req) ; bytes += ret) {
        ret = _DkStreamRead(stream, 0, sizeof(req) - bytes,
                            ((void *) &req) + bytes, NULL, 0);
        if (ret < 0) {
            SGX_DBG(DBG_S, "Attestation Respond: DkStreamRead failed: %d\n", ret);
            goto out;
        }
    }

    SGX_DBG(DBG_S, "Received attestation request ... (mrenclave = %s)\n",
            hex2str(req.mrenclave));

    ret = sgx_get_report(&req.mrenclave, &req.attributes, data, &att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: sgx_get_report failed: %d\n", ret);
        goto out;
    }

    memcpy(att.mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t));
    memcpy(&att.attributes, &pal_sec.enclave_attributes,
           sizeof(sgx_arch_attributes_t));

    SGX_DBG(DBG_S, "Sending attestation ... (mrenclave = %s)\n",
            hex2str(att.mrenclave));

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
            hex2str(att.mrenclave));

    ret = sgx_verify_report(&att.report);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Respond: sgx_verify_report failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Remote attestation not signed by SGX!\n");
        goto out;
    }

    ret = check_mrenclave(&att.report.mrenclave, &att.report.report_data,
                          check_param);
    if (ret < 0) {
        SGX_DBG(DBG_S, "Attestation Request: check_mrenclave failed: %d\n", ret);
        goto out;
    }

    if (ret == 1) {
        SGX_DBG(DBG_S, "Not an allowed encalve (mrenclave = %s)\n",
                hex2str(att.mrenclave));
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    SGX_DBG(DBG_S, "Remote attestation succeed!\n");
    return 0;

out:
    DkStreamDelete(stream, 0);
    return ret;
}
