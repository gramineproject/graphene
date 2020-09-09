/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2017 Fortanix, Inc. */

#include "mbedtls_adapter.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/entropy_poll.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "pal.h"
#include "pal_crypto.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "rng-arch.h"

int mbedtls_to_pal_error(int error) {
    switch (error) {
        case 0:
            return 0;

        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
            return -PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH;

        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return -PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH;

        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return -PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE;

        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
        case MBEDTLS_ERR_DHM_BAD_INPUT_DATA:
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
        case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
        case MBEDTLS_ERR_RSA_PUBLIC_FAILED:  // see mbedtls_rsa_public()
        case MBEDTLS_ERR_RSA_PRIVATE_FAILED: // see mbedtls_rsa_private()
            return -PAL_ERROR_CRYPTO_BAD_INPUT_DATA;

        case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return -PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH;

        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        case MBEDTLS_ERR_DHM_ALLOC_FAILED:
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
        case MBEDTLS_ERR_SSL_ALLOC_FAILED:
        case MBEDTLS_ERR_PK_ALLOC_FAILED:
            return -PAL_ERROR_NOMEM;

        case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
        case MBEDTLS_ERR_RSA_INVALID_PADDING:
            return -PAL_ERROR_CRYPTO_INVALID_PADDING;

        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return -PAL_ERROR_CRYPTO_AUTH_FAILED;

        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return -PAL_ERROR_CRYPTO_INVALID_CONTEXT;

        case MBEDTLS_ERR_DHM_READ_PARAMS_FAILED:
        case MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED:
        case MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED:
        case MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED:
        case MBEDTLS_ERR_DHM_CALC_SECRET_FAILED:
            return -PAL_ERROR_CRYPTO_INVALID_DH_STATE;

        case MBEDTLS_ERR_DHM_INVALID_FORMAT:
            return -PAL_ERROR_CRYPTO_INVALID_FORMAT;

        case MBEDTLS_ERR_DHM_FILE_IO_ERROR:
        case MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return -PAL_ERROR_CRYPTO_IO_ERROR;

        case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return -PAL_ERROR_CRYPTO_KEY_GEN_FAILED;

        case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return -PAL_ERROR_CRYPTO_INVALID_KEY;

        case MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return -PAL_ERROR_CRYPTO_VERIFY_FAILED;

        case MBEDTLS_ERR_RSA_RNG_FAILED:
            return -PAL_ERROR_CRYPTO_RNG_FAILED;

        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            return -PAL_ERROR_TRYAGAIN;

        case MBEDTLS_ERR_NET_CONN_RESET:
            return -PAL_ERROR_CONNFAILED_PIPE;

        default:
            return -PAL_ERROR_DENIED;
    }
}

#define BITS_PER_BYTE 8

/* This is declared in pal_internal.h, but that can't be included here. */
size_t _DkRandomBitsRead(void* buffer, size_t size);

/* Wrapper to provide mbedtls the RNG interface it expects. It passes an
 * extra context parameter, and expects a return value of 0 for success
 * and nonzero for failure. */
static int RandomWrapper(void* private, unsigned char* data, size_t size) {
    __UNUSED(private);
    return _DkRandomBitsRead(data, size);
}

#define BITS_PER_BYTE 8

int lib_SHA256Init(LIB_SHA256_CONTEXT* context) {
    mbedtls_sha256_init(context);
    mbedtls_sha256_starts(context, 0 /* 0 = use SSH256 */);
    return 0;
}

int lib_SHA256Update(LIB_SHA256_CONTEXT* context, const uint8_t* data, size_t data_size) {
    /* For compatibility with other SHA256 providers, don't support
     * large lengths. */
    if (data_size > UINT32_MAX) {
        return -PAL_ERROR_INVAL;
    }
    mbedtls_sha256_update(context, data, data_size);
    return 0;
}

int lib_SHA256Final(LIB_SHA256_CONTEXT* context, uint8_t* output) {
    mbedtls_sha256_finish(context, output);
    /* This function is called free, but it doesn't actually free the memory.
     * It zeroes out the context to avoid potentially leaking information
     * about the hash that was just performed. */
    mbedtls_sha256_free(context);
    return 0;
}

int lib_AESGCMEncrypt(const uint8_t* key, size_t key_size, const uint8_t* iv, const uint8_t* input,
                      size_t input_size, const uint8_t* aad, size_t aad_size, uint8_t* output,
                      uint8_t* tag, size_t tag_size) {
    int ret = -PAL_ERROR_INVAL;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    if (key_size != 16 && key_size != 24 && key_size != 32)
        goto out;

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_size * BITS_PER_BYTE);
    ret = mbedtls_to_pal_error(ret);
    if (ret != 0)
        goto out;

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_size, iv, 12, aad, aad_size,
                                    input, output, tag_size, tag);
    ret = mbedtls_to_pal_error(ret);
    if (ret != 0)
        goto out;

    ret = 0;
out:
    mbedtls_gcm_free(&gcm);
    return ret;
}

int lib_AESGCMDecrypt(const uint8_t* key, size_t key_size, const uint8_t* iv, const uint8_t* input,
                      size_t input_size, const uint8_t* aad, size_t aad_size, uint8_t* output,
                      const uint8_t* tag, size_t tag_size) {
    int ret = -PAL_ERROR_INVAL;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    if (key_size != 16 && key_size != 24 && key_size != 32)
        goto out;

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_size * BITS_PER_BYTE);
    ret = mbedtls_to_pal_error(ret);
    if (ret != 0)
        goto out;

    ret = mbedtls_gcm_auth_decrypt(&gcm, input_size, iv, 12, aad, aad_size, tag, tag_size, input,
                                   output);
    ret = mbedtls_to_pal_error(ret);
    if (ret != 0)
        goto out;

    ret = 0;
out:
    mbedtls_gcm_free(&gcm);
    return ret;
}

int lib_AESCMAC(const uint8_t* key, size_t key_size, const uint8_t* input, size_t input_size,
                uint8_t* mac, size_t mac_size) {
    mbedtls_cipher_type_t cipher;

    switch (key_size) {
        case 16:
            cipher = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 24:
            cipher = MBEDTLS_CIPHER_AES_192_ECB;
            break;
        case 32:
            cipher = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher);

    if (mac_size < cipher_info->block_size) {
        return -PAL_ERROR_INVAL;
    }

    int ret = mbedtls_cipher_cmac(cipher_info, key, key_size * BITS_PER_BYTE, input, input_size,
                                  mac);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACInit(LIB_AESCMAC_CONTEXT* context, const uint8_t* key, size_t key_size) {
    switch (key_size) {
        case 16:
            context->cipher = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 24:
            context->cipher = MBEDTLS_CIPHER_AES_192_ECB;
            break;
        case 32:
            context->cipher = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(context->cipher);

    int ret = mbedtls_cipher_setup(&context->ctx, cipher_info);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    ret = mbedtls_cipher_cmac_starts(&context->ctx, key, key_size * BITS_PER_BYTE);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACUpdate(LIB_AESCMAC_CONTEXT* context, const uint8_t* input, size_t input_size) {
    int ret = mbedtls_cipher_cmac_update(&context->ctx, input, input_size);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACFinish(LIB_AESCMAC_CONTEXT* context, uint8_t* mac, size_t mac_size) {
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(context->cipher);

    int ret = -PAL_ERROR_INVAL;
    if (mac_size < cipher_info->block_size)
        goto exit;

    ret = mbedtls_cipher_cmac_finish(&context->ctx, mac);
    ret = mbedtls_to_pal_error(ret);

exit:
    mbedtls_cipher_free(&context->ctx);
    return ret;
}

int lib_RSAInitKey(LIB_RSA_KEY* key) {
    /* For now, we only need PKCS_V15 type padding. If we need to support
     * multiple padding types, I guess we'll need to add the padding type
     * to this API. We might need to add a wrapper type around the crypto
     * library's key/context type, since not all crypto providers store this
     * in the conext, and instead require you to pass it on each call. */

    /* Last parameter here is the hash type, which is only used for
     * PKCS padding type 2.0. */
    mbedtls_rsa_init(key, MBEDTLS_RSA_PKCS_V15, 0);
    return 0;
}

int lib_RSAGenerateKey(LIB_RSA_KEY* key, uint64_t length_in_bits, uint64_t exponent) {
    if (length_in_bits > UINT_MAX)
        return -PAL_ERROR_INVAL;

    if (exponent > UINT_MAX || (int)exponent < 0)
        return -PAL_ERROR_INVAL;

    int ret = mbedtls_rsa_gen_key(key, RandomWrapper, NULL, length_in_bits, exponent);
    return mbedtls_to_pal_error(ret);
}

int lib_RSAExportPublicKey(LIB_RSA_KEY* key, uint8_t* e, size_t* e_size, uint8_t* n,
                           size_t* n_size) {
    /* Public exponent. */
    int ret = mbedtls_mpi_write_binary(&key->E, e, *e_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* Modulus. */
    ret = mbedtls_mpi_write_binary(&key->N, n, *n_size);
    return mbedtls_to_pal_error(ret);
}

int lib_RSAImportPublicKey(LIB_RSA_KEY* key, const uint8_t* e, size_t e_size, const uint8_t* n,
                           size_t n_size) {
    int ret;

    /* Public exponent. */
    ret = mbedtls_mpi_read_binary(&key->E, e, e_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* Modulus. */
    ret = mbedtls_mpi_read_binary(&key->N, n, n_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* This length is in bytes. */
    key->len = (mbedtls_mpi_bitlen(&key->N) + 7) >> 3;

    return 0;
}

int lib_RSAVerifySHA256(LIB_RSA_KEY* key, const uint8_t* hash, size_t hash_size,
                        const uint8_t* signature, size_t signature_size) {
    /* The mbedtls decrypt API assumes that you have a memory buffer that
     * is as large as the key size and take the length as a parameter. We
     * check, so that in the event the caller makes a mistake, you'll get
     * an error instead of reading off the end of the buffer. */
    if (signature_size != key->len)
        return -PAL_ERROR_INVAL;

    int ret = mbedtls_rsa_pkcs1_verify(key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                       hash_size, hash, signature);

    return mbedtls_to_pal_error(ret);
}

int lib_RSAFreeKey(LIB_RSA_KEY* key) {
    mbedtls_rsa_free(key);
    return 0;
}

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t* olen) {
    __UNUSED(data);
    assert(output && olen);
    *olen = 0;

    unsigned long long rand64;
    for (size_t i = 0; i < len; i += sizeof(rand64)) {
        rand64 = get_rand64();
        size_t over = i + sizeof(rand64) < len ? 0 : i + sizeof(rand64) - len;
        memcpy(output + i, &rand64, sizeof(rand64) - over);
    }

    *olen = len;
    return 0;
}

static int recv_cb(void* ctx, uint8_t* buf, size_t buf_size) {
    LIB_SSL_CONTEXT* ssl_ctx = (LIB_SSL_CONTEXT*)ctx;
    int fd = ssl_ctx->stream_fd;
    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    if (buf_size > INT_MAX) {
        /* pal_recv_cb cannot receive more than 32-bit limit, trim buf_size to fit in 32-bit */
        buf_size = INT_MAX;
    }
    ssize_t ret = ssl_ctx->pal_recv_cb(fd, buf, buf_size);

    if (ret < 0) {
        if (ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        if (ret == -EPIPE)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;
}

static int send_cb(void* ctx, uint8_t const* buf, size_t buf_size) {
    LIB_SSL_CONTEXT* ssl_ctx = (LIB_SSL_CONTEXT*)ctx;
    int fd = ssl_ctx->stream_fd;
    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    if (buf_size > INT_MAX) {
        /* pal_send_cb cannot send more than 32-bit limit, trim buf_size to fit in 32-bit */
        buf_size = INT_MAX;
    }
    ssize_t ret = ssl_ctx->pal_send_cb(fd, buf, buf_size);
    if (ret < 0) {
        if (ret == -EINTR || ret == -EAGAIN || ret == -EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (ret == -EPIPE)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

/*! This function is not thread-safe; caller is responsible for proper synchronization. */
int lib_SSLInit(LIB_SSL_CONTEXT* ssl_ctx, int stream_fd, bool is_server, const uint8_t* psk,
                size_t psk_size, ssize_t (*pal_recv_cb)(int fd, void* buf, size_t buf_size),
                ssize_t (*pal_send_cb)(int fd, const void* buf, size_t buf_size),
                const uint8_t* buf_load_ssl_ctx, size_t buf_size) {
    int ret;

    memset(ssl_ctx, 0, sizeof(*ssl_ctx));

    ssl_ctx->ciphersuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256;
    memset(&ssl_ctx->ciphersuites[1], 0, sizeof(ssl_ctx->ciphersuites[1]));

    ssl_ctx->pal_recv_cb = pal_recv_cb;
    ssl_ctx->pal_send_cb = pal_send_cb;
    ssl_ctx->stream_fd   = stream_fd;

    mbedtls_entropy_init(&ssl_ctx->entropy);
    mbedtls_ctr_drbg_init(&ssl_ctx->ctr_drbg);
    mbedtls_ssl_config_init(&ssl_ctx->conf);
    mbedtls_ssl_init(&ssl_ctx->ssl);

    ret = mbedtls_ctr_drbg_seed(&ssl_ctx->ctr_drbg, mbedtls_entropy_func, &ssl_ctx->entropy, NULL,
                                0);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    ret = mbedtls_ssl_config_defaults(&ssl_ctx->conf,
                                      is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    mbedtls_ssl_conf_rng(&ssl_ctx->conf, mbedtls_ctr_drbg_random, &ssl_ctx->ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&ssl_ctx->conf, ssl_ctx->ciphersuites);

    const unsigned char psk_identity[] = "dummy";
    ret = mbedtls_ssl_conf_psk(&ssl_ctx->conf, psk, psk_size, psk_identity,
                               sizeof(psk_identity) - 1);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    ret = mbedtls_ssl_setup(&ssl_ctx->ssl, &ssl_ctx->conf);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    mbedtls_ssl_set_bio(&ssl_ctx->ssl, ssl_ctx, send_cb, recv_cb, NULL);

    if (buf_load_ssl_ctx && buf_size) {
        /* SSL context was serialized, must be restored from the supplied buffer */
        ret = mbedtls_ssl_context_load(&ssl_ctx->ssl, buf_load_ssl_ctx, buf_size);
        if (ret != 0)
            return mbedtls_to_pal_error(ret);
    }

    return 0;
}

int lib_SSLFree(LIB_SSL_CONTEXT* ssl_ctx) {
    mbedtls_ssl_free(&ssl_ctx->ssl);
    mbedtls_ssl_config_free(&ssl_ctx->conf);
    mbedtls_ctr_drbg_free(&ssl_ctx->ctr_drbg);
    mbedtls_entropy_free(&ssl_ctx->entropy);
    return 0;
}

int lib_SSLHandshake(LIB_SSL_CONTEXT* ssl_ctx) {
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl_ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            break;
    }
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    return 0;
}

int lib_SSLRead(LIB_SSL_CONTEXT* ssl_ctx, uint8_t* buf, size_t buf_size) {
    int ret = mbedtls_ssl_read(&ssl_ctx->ssl, buf, buf_size);
    if (ret == 0)
        return -PAL_ERROR_ENDOFSTREAM;
    if (ret < 0)
        return mbedtls_to_pal_error(ret);
    return ret;
}

int lib_SSLWrite(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t* buf, size_t buf_size) {
    int ret = mbedtls_ssl_write(&ssl_ctx->ssl, buf, buf_size);
    if (ret <= 0)
        return mbedtls_to_pal_error(ret);
    return ret;
}

int lib_SSLSave(LIB_SSL_CONTEXT* ssl_ctx, uint8_t* buf, size_t buf_size, size_t* out_size) {
    int ret = mbedtls_ssl_context_save(&ssl_ctx->ssl, buf, buf_size, out_size);
    if (ret == MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        return -PAL_ERROR_NOMEM;
    } else if (ret < 0) {
        return -PAL_ERROR_DENIED;
    }
    return 0;
}
