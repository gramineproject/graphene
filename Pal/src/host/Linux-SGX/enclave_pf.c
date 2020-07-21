/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#include <linux/fs.h>

#include "pal_crypto.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "spinlock.h"

/*
 * At startup, protected file paths are read from the manifest and the specified files
 * or directories registered. For supported I/O operations, handlers (in db_files.c)
 * check if the file is a PF to perform the required operation transparently.
 *
 * Since PF's "logical" size is different than the real FS size (and to avoid potential
 * infinite recursion in FS handlers) we don't use PAL file APIs here, but raw OCALLs.
 */

/* List of map buffers */
LISTP_TYPE(pf_map) g_pf_map_list = LISTP_INIT;

/* Callbacks for protected files handling */
static pf_status_t cb_read(pf_handle_t handle, void* buffer, uint64_t offset, size_t size) {
    int fd = *(int*)handle;
    size_t buffer_offset = 0;
    size_t to_read = size;
    while (to_read > 0) {
        ssize_t read = ocall_pread(fd, buffer + buffer_offset, to_read, offset + buffer_offset);
        if (read == -EINTR)
            continue;

        if (read < 0) {
            SGX_DBG(DBG_E, "cb_read(%d, %p, %lu, %lu): read failed: %ld\n",
                    fd, buffer, offset, size, read);
            return PF_STATUS_CALLBACK_FAILED;
        }

        /* EOF is an error condition, we want to read exactly `size` bytes */
        if (read == 0) {
            SGX_DBG(DBG_E, "cb_read(%d, %p, %lu, %lu): EOF\n", fd, buffer, offset, size);
            return PF_STATUS_CALLBACK_FAILED;
        }

        to_read -= read;
        buffer_offset += read;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_write(pf_handle_t handle, const void* buffer, uint64_t offset, size_t size) {
    int fd = *(int*)handle;
    size_t buffer_offset = 0;
    size_t to_write = size;
    while (to_write > 0) {
        ssize_t written = ocall_pwrite(fd, buffer + buffer_offset, to_write,
                                       offset + buffer_offset);
        if (written == -EINTR)
            continue;

        if (written < 0) {
            SGX_DBG(DBG_E, "cb_write(%d, %p, %lu, %lu): write failed: %ld\n",
                    fd, buffer, offset, size, written);
            return PF_STATUS_CALLBACK_FAILED;
        }

        /* EOF is an error condition, we want to write exactly `size` bytes */
        if (written == 0) {
            SGX_DBG(DBG_E, "cb_write(%d, %p, %lu, %lu): EOF\n", fd, buffer, offset, size);
            return PF_STATUS_CALLBACK_FAILED;
        }

        to_write -= written;
        buffer_offset += written;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_truncate(pf_handle_t handle, uint64_t size) {
    int fd = *(int*)handle;
    int ret = ocall_ftruncate(fd, size);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_truncate(%d, %lu): ocall failed: %d\n", fd, size, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

#ifdef DEBUG
static void cb_debug(const char* msg) {
    SGX_DBG(DBG_D, "%s", msg);
}
#endif

static pf_status_t cb_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv,
                                      const void* aad, size_t aad_size,
                                      const void* input, size_t input_size, void* output,
                                      pf_mac_t* mac) {
    int ret = lib_AESGCMEncrypt((const uint8_t*)key, sizeof(*key), (const uint8_t*)iv, input,
                                input_size, aad, aad_size, output, (uint8_t*)mac, sizeof(*mac));
    if (ret != 0) {
        SGX_DBG(DBG_E, "lib_AESGCMEncrypt failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv,
                                      const void* aad, size_t aad_size,
                                      const void* input, size_t input_size, void* output,
                                      const pf_mac_t* mac) {
    int ret = lib_AESGCMDecrypt((const uint8_t*)key, sizeof(*key), (const uint8_t*)iv, input,
                                input_size, aad, aad_size, output, (const uint8_t*)mac,
                                sizeof(*mac));
    if (ret != 0) {
        SGX_DBG(DBG_E, "lib_AESGCMDecrypt failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_random(uint8_t* buffer, size_t size) {
    int ret = _DkRandomBitsRead(buffer, size);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "_DkRandomBitsRead failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

/* Wrap key for protected files, either hard-coded in manifest or provisioned during attestation */
static pf_key_t g_pf_wrap_key = {0};
static bool g_pf_wrap_key_set = false;

/* Collection of registered protected files */
static struct protected_file* g_protected_files = NULL;

/* Collection of registered protected directories */
static struct protected_file* g_protected_dirs = NULL;

/* Lock for operations on global PF structures */
static spinlock_t g_protected_file_lock = INIT_SPINLOCK_UNLOCKED;

/* Take ownership of the global PF lock */
void pf_lock(void) {
    spinlock_lock(&g_protected_file_lock);
}

/* Release ownership of the global PF lock */
void pf_unlock(void) {
    spinlock_unlock(&g_protected_file_lock);
}

/* Exact match of path in g_protected_files */
struct protected_file* find_protected_file(const char* path) {
    struct protected_file* pf = NULL;

    pf_lock();
    HASH_FIND_STR(g_protected_files, path, pf);
    pf_unlock();
    return pf;
}

/* Find registered pf directory starting with the given path */
static struct protected_file* find_protected_dir(const char* path) {
    struct protected_file* pf  = NULL;
    struct protected_file* tmp = NULL;
    size_t len = strlen(path);

    pf_lock();
    // TODO: avoid linear lookup
    for (tmp = g_protected_dirs; tmp != NULL; tmp = tmp->hh.next) {
        if (tmp->path_len < len &&
                !memcmp(tmp->path, path, tmp->path_len) &&
                (!path[tmp->path_len] || path[tmp->path_len] == '/')) {
            pf = tmp;
            break;
        }
    }

    pf_unlock();
    return pf;
}

/* Find PF by handle */
struct protected_file* find_protected_file_handle(PAL_HANDLE handle) {
    char uri[URI_MAX];
    int uri_len;

    /* TODO: this logic is inefficient, add a PF reference to PAL_HANDLE instead */
    uri_len = _DkStreamGetName(handle, uri, URI_MAX);
    if (uri_len < 0)
        return NULL;

    /* uri is prefixed by "file:", we need path */
    assert(strstartswith_static(uri, URI_PREFIX_FILE));
    return find_protected_file(uri + URI_PREFIX_FILE_LEN);
}

static int register_protected_path(const char* path, struct protected_file** new_pf);

/* Return a registered PF that matches specified path
   (or the path that is contained in a registered PF directory) */
struct protected_file* get_protected_file(const char* path) {
    struct protected_file* pf = find_protected_file(path);
    if (pf)
        goto out;

    pf = find_protected_dir(path);
    if (pf) {
        /* path not registered but matches registered dir */
        SGX_DBG(DBG_D, "get_pf: registering new PF '%s' in dir '%s'\n", path, pf->path);
        int ret = register_protected_path(path, &pf);
        __UNUSED(ret);
        assert(ret == 0);
        /* return newly registered PF */
    }

out:
    return pf;
}

#define S_ISDIR(m) ((m & 0170000) == 0040000)

static int is_directory(const char* path, bool* is_dir) {
    int fd = -1;
    struct stat st;

    *is_dir = false;
    int ret = ocall_open(path, O_RDONLY, 0);
    if (IS_ERR(ret)) {
        /* this can be called on a path without the file existing, assume non-dir for now */
        ret = 0;
        goto out;
    }

    fd = ret;
    ret = ocall_fstat(fd, &st);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "is_directory(%s): fstat failed: %d\n", path, ret);
        goto out;
    }

    if (S_ISDIR(st.st_mode))
        *is_dir = true;

out:
    if (fd >= 0) {
        int rv = ocall_close(fd);
        if (IS_ERR(rv)) {
            SGX_DBG(DBG_E, "is_directory(%s): close failed: %d\n", path, rv);
        }
    }

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

/* Register all files from the given directory recursively */
static int register_protected_dir(const char* path) {
    int fd = -1;
    int ret = -PAL_ERROR_NOMEM;
    size_t bufsize = 1024;
    void* buf = malloc(bufsize);

    if (!buf)
        return -PAL_ERROR_NOMEM;

    ret = ocall_open(path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "register_protected_dir: opening %s failed: %d\n", path, ret);
        ret = unix_to_pal_error(ERRNO(ret));
        goto out;
    }
    fd = ret;

    size_t path_size = strlen(path) + 1;
    int returned;
    do {
        returned = ocall_getdents(fd, buf, bufsize);
        if (IS_ERR(returned)) {
            ret = unix_to_pal_error(ERRNO(returned));
            SGX_DBG(DBG_E, "register_protected_dir: reading %s failed: %d\n", path, ret);
            goto out;
        }

        int pos = 0;
        struct linux_dirent64* dir;

        while (pos < returned) {
            dir = (struct linux_dirent64*)((char*)buf + pos);

            if (!strcmp_static(dir->d_name, ".") || !strcmp_static(dir->d_name, ".."))
                goto next;

            /* register file */
            size_t sub_path_size = URI_PREFIX_FILE_LEN + path_size + 1 + strlen(dir->d_name);
            char* sub_path = malloc(sub_path_size);
            ret = -PAL_ERROR_NOMEM;
            if (!sub_path)
                goto out;

            snprintf(sub_path, sub_path_size, URI_PREFIX_FILE "%s/%s", path, dir->d_name);
            ret = register_protected_path(sub_path, NULL);
            if (ret != 0) {
                free(sub_path);
                goto out;
            }
            free(sub_path);
next:
            pos += dir->d_reclen;
        }
    } while (returned != 0);

    ret = 0;
out:
    if (fd >= 0)
        ocall_close(fd);
    free(buf);
    return ret;
}

/* Register a single PF (if it's a directory, recursively) */
static int register_protected_path(const char* path, struct protected_file** new_pf) {
    int ret = -PAL_ERROR_NOMEM;
    struct protected_file* new = NULL;

    char* normpath = malloc(URI_MAX);
    if (!normpath)
        goto out;

    size_t len = URI_MAX;
    ret = get_norm_path(path, normpath, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Couldn't normalize path (%s): %s\n", path, pal_strerror(ret));
        goto out;
    }

    /* discard the "file:" prefix */
    if (strstartswith_static(normpath, URI_PREFIX_FILE))
        path = normpath + URI_PREFIX_FILE_LEN;
    else
        path = normpath;

    if (find_protected_file(path)) {
        ret = 0;
        SGX_DBG(DBG_D, "register_protected_path: file %s already registered\n", path);
        goto out;
    }

    new = calloc(1, sizeof(*new));
    if (!new) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    new->path_len = strlen(path);
    /* This is never freed but so isn't the whole struct, PFs persist for the whole lifetime
       of the process. */
    new->path = malloc(new->path_len + 1);
    if (!new->path) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    memcpy(new->path, path, new->path_len + 1);
    new->refcount = 0;
    new->writable_fd = -1;

    bool is_dir;
    ret = is_directory(path, &is_dir);
    if (ret < 0)
        goto out;

    SGX_DBG(DBG_D, "register_protected_path: [%s] %s = %p\n", is_dir ? "dir" : "file", path, new);

    if (is_dir)
        register_protected_dir(path);

    pf_lock();

    if (is_dir) {
        HASH_ADD_STR(g_protected_dirs, path, new);
    } else {
        HASH_ADD_STR(g_protected_files, path, new);
    }

    pf_unlock();

    if (new_pf)
        *new_pf = new;

    ret = 0;
out:
    free(normpath);
    if (ret < 0) {
        if (new)
            free(new->path);
        free(new);
    }
    return ret;
}

/* Read PF paths from manifest and register them */
static int register_protected_files(const char* key_prefix) {
    char* cfgbuf = NULL;
    int ret = -PAL_ERROR_DENIED;
    ssize_t cfgsize = get_config_entries_size(g_pal_state.root_config, key_prefix);
    if (cfgsize <= 0)
        goto out;

    cfgbuf = malloc(cfgsize);
    if (!cfgbuf) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    int uris_count = get_config_entries(g_pal_state.root_config, key_prefix, cfgbuf, cfgsize);
    if (uris_count == -PAL_ERROR_INVAL) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    char key[CONFIG_MAX];
    char uri[CONFIG_MAX];
    char* key_suffix = cfgbuf;

    for (int i = 0; i < uris_count; i++) {
        size_t len = strlen(key_suffix);
        snprintf(key, CONFIG_MAX, "%s.%s", key_prefix, key_suffix);
        key_suffix += len + 1;
        len = get_config(g_pal_state.root_config, key, uri, CONFIG_MAX);
        if (len > 0) {
            if (!strstartswith_static(uri, URI_PREFIX_FILE)) {
                SGX_DBG(DBG_E, "Invalid URI [%s]: URIs of protected files must start with '"
                        URI_PREFIX_FILE "'\n", uri);
            } else {
                register_protected_path(uri, NULL);
            }
        } else {
            SGX_DBG(DBG_E, "Invalid PF entry in manifest: '%s'\n", key);
        }
    }

    pf_lock();
    SGX_DBG(DBG_D, "Registered %u protected directories and %u protected files\n",
            HASH_COUNT(g_protected_dirs), HASH_COUNT(g_protected_files));
    pf_unlock();
    ret = 0;
out:
    free(cfgbuf);
    return ret;
}

#define PF_MANIFEST_KEY_PREFIX "sgx.protected_files_key"
#define PF_MANIFEST_PATH_PREFIX "sgx.protected_files"

/* Initialize the PF library, register PFs from the manifest */
int init_protected_files(void) {
    pf_debug_f debug_callback = NULL;

#ifdef DEBUG
    debug_callback = cb_debug;
#endif

    pf_set_callbacks(cb_read, cb_write, cb_truncate, cb_aes_gcm_encrypt, cb_aes_gcm_decrypt,
                     cb_random, debug_callback);

    char key_hex[PF_KEY_SIZE * 2 + 1];
    ssize_t len = get_config(g_pal_state.root_config, PF_MANIFEST_KEY_PREFIX, key_hex,
                             sizeof(key_hex));
    if (len <= 0) {
        /* wrap key is not hard-coded in the manifest, assume that it will be provisioned after
         * local/remote attestation and clear it for now */
        g_pf_wrap_key_set = false;
    } else {
        if (len != sizeof(key_hex) - 1) {
            SGX_DBG(DBG_E, "Malformed " PF_MANIFEST_KEY_PREFIX " value in the manifest\n");
            return -PAL_ERROR_INVAL;
        }

        memset(g_pf_wrap_key, 0, sizeof(g_pf_wrap_key));
        for (ssize_t i = 0; i < len; i++) {
            int8_t val = hex2dec(key_hex[i]);
            if (val < 0) {
                SGX_DBG(DBG_E, "Malformed " PF_MANIFEST_KEY_PREFIX " value in the manifest\n");
                return -PAL_ERROR_INVAL;
            }
            g_pf_wrap_key[i/2] = g_pf_wrap_key[i/2] * 16 + (uint8_t)val;
        }
        g_pf_wrap_key_set = true;
    }

    if (register_protected_files(PF_MANIFEST_PATH_PREFIX) < 0) {
        SGX_DBG(DBG_E, PF_MANIFEST_PATH_PREFIX "key not found in manifest, "
                "protected files will not be available\n");
    }

    return 0;
}

/* Open/create a PF */
static int open_protected_file(const char* path, struct protected_file* pf, pf_handle_t handle,
                               uint64_t size, pf_file_mode_t mode, bool create) {
    if (!g_pf_wrap_key_set) {
        SGX_DBG(DBG_E, "pf_open(%d, %s) failed: wrap key was not provided\n", *(int*)handle, path);
        return -PAL_ERROR_DENIED;
    }

    pf_status_t pfs;
    pfs = pf_open(handle, path, size, mode, create, &g_pf_wrap_key, &pf->context);
    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "pf_open(%d, %s) failed: %d\n", *(int*)handle, path, pfs);
        return -PAL_ERROR_DENIED;
    }
    return 0;
}

/* Prepare a PF for I/O
   This function registers the PF if path is in a registered PF directory, then
   calls the appropriate PF function to open/create it (if allowed) */
struct protected_file* load_protected_file(const char* path, int* fd, uint64_t size,
                                           pf_file_mode_t mode, bool create,
                                           struct protected_file* pf) {
    SGX_DBG(DBG_D, "load_protected_file: %s, fd %d, size %lu, mode %d, create %d, pf %p\n",
            path, *fd, size, mode, create, pf);

    if (!pf)
        pf = get_protected_file(path);

    if (pf) {
        if (!pf->context) {
            SGX_DBG(DBG_D, "load_protected_file: %s, fd %d: opening new PF %p\n", path, *fd, pf);
            int ret = open_protected_file(path, pf, (pf_handle_t)fd, size, mode, create);
            if (ret < 0)
                return NULL;
        } else {
            SGX_DBG(DBG_D, "load_protected_file: %s, fd %d: returning old PF %p\n", path, *fd, pf);
        }
    }

    return pf;
}

/* Flush PF map buffers and optionally remove and free them.
 * If pf is NULL, process all maps containing given buffer.
 * If buffer is NULL, process all maps for given pf.
 * If both pf and buffer are NULL, process all maps for all PFs.
 */
int flush_pf_maps(struct protected_file* pf, void* buffer, bool remove) {
    struct pf_map* map;
    struct pf_map* tmp;
    uint64_t pf_size;
    pf_status_t pfs;

    SGX_DBG(DBG_D, "flush_pf_maps: pf %p, buf %p, remove %d\n", pf, buffer, remove);

    pf_lock();
    LISTP_FOR_EACH_ENTRY_SAFE(map, tmp, &g_pf_map_list, list) {
        if (pf && map->pf != pf)
            continue;

        if (buffer && map->buffer != buffer)
            continue;

        size_t map_size = map->size;
        struct protected_file* map_pf = pf ? pf : map->pf;

        pfs = pf_get_size(map_pf->context, &pf_size);
        assert(PF_SUCCESS(pfs));

        SGX_DBG(DBG_D, "flush_pf_maps: pf %p, buf %p, map size %lu, offset %lu\n",
                map_pf, map->buffer, map_size, map->offset);

        assert(pf_size >= map->offset);
        if (map->offset + map_size > pf_size)
            map_size = pf_size - map->offset;

        if (map_size > 0) {
            pfs = pf_write(map_pf->context, map->offset, map_size, map->buffer);
            if (PF_FAILURE(pfs)) {
                SGX_DBG(DBG_E, "flush_pf_maps: pf_write failed: %d\n", pfs);
                pf_unlock();
                return -PAL_ERROR_INVAL;
            }
        }

        if (remove) {
            LISTP_DEL(map, &g_pf_map_list, list);
            free(map);
        }
    }

    pf_unlock();
    return 0;
}

/* Flush map buffers and unload/close the PF */
int unload_protected_file(struct protected_file* pf) {
    /* flush all pf's maps and delete them */
    int ret = flush_pf_maps(pf, NULL, true);
    if (ret < 0)
        return ret;
    pf_status_t pfs = pf_close(pf->context);
    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "unload_protected_file(%p) failed: %d\n", pf, pfs);
    }

    pf->context = NULL;
    return 0;
}

int set_protected_files_key(const char* pf_key_hex) {
    size_t pf_key_hex_len = strlen(pf_key_hex);
    if (pf_key_hex_len != PF_KEY_SIZE * 2) {
        return -PAL_ERROR_INVAL;
    }

    pf_lock();
    memset(g_pf_wrap_key, 0, sizeof(g_pf_wrap_key));
    for (size_t i = 0; i < pf_key_hex_len; i++) {
        int8_t val = hex2dec(pf_key_hex[i]);
        if (val < 0) {
            memset(g_pf_wrap_key, 0, sizeof(g_pf_wrap_key));
            pf_unlock();
            return -PAL_ERROR_INVAL;
        }
        g_pf_wrap_key[i/2] = g_pf_wrap_key[i/2] * 16 + (uint8_t)val;
    }
    g_pf_wrap_key_set = true;
    pf_unlock();

    return 0;
}
