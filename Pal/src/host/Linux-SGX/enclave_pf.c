/* Copyright (C) 2018-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>

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

#include <linux/fs.h>
#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_internal.h>
#include <pal_crypto.h>
#include <spinlock.h>

/*
At startup, protected file paths are read from the manifest and the specified files
or directories registered. For supported I/O operations, handlers (in db_files.c)
check if the file is a PF to perform the required operation transparently.

Since PF's "logical" size is different than the real FS size (and to avoid potential
infinite recursion in FS handlers) we don't use PAL file APIs here, but raw OCALLs.
*/

/* List of map buffers */
LISTP_TYPE(pf_map) g_pf_map_list = LISTP_INIT;

/* Callbacks for protected files handling */
static void* cb_malloc(size_t size) {
    void* address = malloc(size);
    if (address)
        memset(address, 0, size);
    return address;
}

static pf_status_t cb_read(pf_handle_t handle, void* buffer, size_t offset, size_t size) {
    int fd  = *(int*)handle;
    int ret = ocall_lseek(fd, offset, SEEK_SET);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_read(%d, %p, %lu, %lu): lseek failed: %d\n",
                fd, buffer, offset, size, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }

    size_t offs = 0;
    while (size > 0) {
        ssize_t read = ocall_read(fd, buffer + offs, size);
        if (read == -EINTR)
            continue;
        if (read <= 0) {
            SGX_DBG(DBG_E, "cb_read(%d, %p, %lu, %lu): read failed: %ld\n",
                    fd, buffer, offset, size, read);
            return PF_STATUS_CALLBACK_FAILED;
        }
        size -= read;
        offs += read;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_write(pf_handle_t handle, void* buffer, size_t offset, size_t size) {
    int fd  = *(int*)handle;
    int ret = ocall_lseek(fd, offset, SEEK_SET);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_write(%d, %p, %lu, %lu): lseek failed: %d\n",
            fd, buffer, offset, size, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }

    size_t offs = 0;
    while (size > 0) {
        ssize_t written = ocall_write(fd, buffer + offs, size);
        if (written == -EINTR)
            continue;
        if (written <= 0) {
            SGX_DBG(DBG_E, "cb_write(%d, %p, %lu, %lu): write failed: %ld\n",
                    fd, buffer, offset, size, written);
            return PF_STATUS_CALLBACK_FAILED;
        }
        size -= written;
        offs += written;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_truncate(pf_handle_t handle, size_t size) {
    int fd  = *(int*)handle;
    int ret = ocall_ftruncate(fd, size);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_truncate(%d, %lu): ocall failed: %d\n", fd, size, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_flush(pf_handle_t handle) {
    int fd  = *(int*)handle;
    int ret = ocall_fsync(fd);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_flush(%d): ocall failed: %d\n", fd, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_open(const char* path, pf_file_mode_t mode, pf_handle_t* handle,
                           size_t* size) {
    // TODO (only used for recovery files)
    __UNUSED(path);
    __UNUSED(mode);
    __UNUSED(handle);
    __UNUSED(size);
    return PF_STATUS_NOT_IMPLEMENTED;
}

static pf_status_t cb_close(pf_handle_t handle) {
    int fd  = *(int*)handle;
    int ret = ocall_close(fd);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_close(%d): ocall failed: %d\n", fd, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

static pf_status_t cb_delete(const char* path) {
    int ret = ocall_delete(path);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "cb_delete(%s): ocall failed: %d\n", path, ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

#ifdef DEBUG
static void cb_debug(const char* msg) {
    SGX_DBG(DBG_D, "%s", msg);
}
#endif

static pf_status_t cb_crypto_aes_gcm_encrypt(const pf_key_t* key, const pf_iv_t* iv,
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

static pf_status_t cb_crypto_aes_gcm_decrypt(const pf_key_t* key, const pf_iv_t* iv,
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

static pf_status_t cb_crypto_random(uint8_t* buffer, size_t size) {
    int ret = _DkRandomBitsRead(buffer, size);
    if (ret < 0) {
        SGX_DBG(DBG_E, "_DkRandomBitsRead failed: %d\n", ret);
        return PF_STATUS_CALLBACK_FAILED;
    }
    return PF_STATUS_SUCCESS;
}

/* Wrap key for protected files.
   TODO: In the future, this key should be provisioned after local/remote attestation. */
static pf_key_t g_pf_wrap_key = {0};

static LISTP_TYPE(protected_file) protected_file_list = LISTP_INIT;
static LISTP_TYPE(protected_file) protected_dir_list = LISTP_INIT;
static spinlock_t protected_file_lock = INIT_SPINLOCK_UNLOCKED;

#define FILE_URI_PREFIX "file:"
#define FILE_URI_PREFIX_LEN strlen(FILE_URI_PREFIX)

/* Exact match of path in protected_file_list */
struct protected_file* find_protected_file(const char* path) {
    struct protected_file* pf  = NULL;
    struct protected_file* tmp = NULL;
    size_t len                 = strlen(path);

    spinlock_lock(&protected_file_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &protected_file_list, list) {
        /* files: must be exactly the same URI */
        if (tmp->path_len == len && !memcmp(tmp->path, path, len + 1)) {
            pf = tmp;
            break;
        }
    }

    spinlock_unlock(&protected_file_lock);
    return pf;
}

/* Find registered pf directory starting with the given path */
struct protected_file* find_protected_dir(const char* path) {
    struct protected_file* pf  = NULL;
    struct protected_file* tmp = NULL;
    size_t len                 = strlen(path);

    spinlock_lock(&protected_file_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &protected_dir_list, list) {
        if (tmp->path_len < len &&
            !memcmp(tmp->path, path, tmp->path_len) &&
            (!path[tmp->path_len] || path[tmp->path_len] == '/')) {
            pf = tmp;
            break;
        }
    }

    spinlock_unlock(&protected_file_lock);
    return pf;
}

/* Find PF by handle */
struct protected_file* find_protected_file_handle(PAL_HANDLE handle) {
    char uri[URI_MAX];
    int uri_len;

    uri_len = _DkStreamGetName(handle, uri, URI_MAX);
    if (uri_len < 0)
        return NULL;

    /* uri is prefixed by "file:", we need path */
    return find_protected_file(uri + FILE_URI_PREFIX_LEN);
}

static int register_protected_path(const char* path, struct protected_file** new_pf);

/* Return a registered PF that matches specified path
   (or the path is contained in a registered PF directory) */
struct protected_file* get_protected_file(const char* path) {
    struct protected_file* pf = find_protected_file(path);
    if (pf)
        goto out;

    pf = find_protected_dir(path);
    if (pf) {
        /* path not registered but matches registered dir */
        SGX_DBG(DBG_D, "is_pf: registering new PF '%s' in dir '%s'\n", path, pf->path);
        __attribute__((unused)) int ret = register_protected_path(path, &pf);
        assert(ret == 0);
        /* return newly registered PF */
    }

out:
    SGX_DBG(DBG_D, "get_pf(%s) = %p\n", path, pf);
    return pf;
}

#define	S_ISDIR(m)	((m & 0170000) == 0040000)

static int is_directory(const char* path, bool* is_dir) {
    int fd = -1;
    struct stat st;

    *is_dir = false;
    int ret = ocall_open(path, O_RDONLY, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "is_directory(%s): open failed: %d\n", path, ret);
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
        int rv;
        if ((rv = ocall_close(fd)) < 0) {
            SGX_DBG(DBG_E, "is_directory(%s): close failed: %d\n", path, rv);
        }
    }

    return unix_to_pal_error(ERRNO(ret));
}

/* Register all files from the given directory recursively */
static int register_protected_dir(const char* path) {
    int fd         = -1;
    int ret        = -PAL_ERROR_NOMEM;
    size_t bufsize = 1024;
    void* buf      = malloc(bufsize);

    if (!buf)
        return -PAL_ERROR_NOMEM;

    ret = ocall_open(path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "register_protected_dir: opening %s failed: %d\n", path, ret);
        goto out;
    }
    fd = ret;

    size_t path_size = strlen(path) + 1;
    int returned;
    do {
        returned = ocall_getdents(fd, buf, bufsize);
        if (IS_ERR(returned)) {
            ret = returned;
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
            size_t sub_path_size = strlen(dir->d_name) + 1 + path_size + FILE_URI_PREFIX_LEN;
            char* sub_path = (char*)malloc(sub_path_size);
            ret = -PAL_ERROR_NOMEM;
            if (!sub_path)
                goto out;

            snprintf(sub_path, sub_path_size, FILE_URI_PREFIX "%s/%s", path, dir->d_name);
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
    char normpath[URI_MAX];

    size_t len = URI_MAX;
    int ret    = get_norm_path(path, normpath, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Couldn't normalize path (%s): %s\n", path, pal_strerror(ret));
        return ret;
    }

    /* discard the "file:" prefix */
    if (strstartswith_static(normpath, FILE_URI_PREFIX))
        path = normpath + FILE_URI_PREFIX_LEN;
    else
        path = normpath;

    struct protected_file* new;

    if (find_protected_file(path)) {
        SGX_DBG(DBG_D, "register_protected_path: file %s already registered\n", path);
        return 0;
    }

    new = malloc(sizeof(struct protected_file));
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);

    memset(new, 0, sizeof(struct protected_file));

    new->path_len = strlen(path);
    memcpy(new->path, path, new->path_len + 1);
    new->refcount = 0;

    bool is_dir;
    ret = is_directory(path, &is_dir);
    if (ret != 0) {
        free(new);
        return ret;
    }
    SGX_DBG(DBG_D, "register_protected_path: [%s] %s\n", is_dir ? "dir" : "file", path);

    if (is_dir)
        register_protected_dir(path);

    spinlock_lock(&protected_file_lock);

    if (is_dir) {
        LISTP_ADD_TAIL(new, &protected_dir_list, list);
    } else {
        LISTP_ADD_TAIL(new, &protected_file_list, list);
    }

    spinlock_unlock(&protected_file_lock);

    if (new_pf)
        *new_pf = new;

    return 0;
}

/* Read PF paths from manifest and register them */
static int register_protected_files(const char* key_prefix) {
    char* cfgbuf    = NULL;
    int ret         = -1;
    ssize_t cfgsize = get_config_entries_size(pal_state.root_config, key_prefix);
    if (cfgsize <= 0)
        goto out;

    cfgbuf = (char*)malloc(cfgsize);
    int nuris = get_config_entries(pal_state.root_config, key_prefix, cfgbuf, cfgsize);
    if (nuris == -PAL_ERROR_INVAL)
        nuris = 0;

    if (nuris >= 0) {
        char key[CONFIG_MAX], uri[CONFIG_MAX];
        char* k = cfgbuf;

        for (int i = 0 ; i < nuris ; i++) {
            int len = strlen(k);
            snprintf(key, CONFIG_MAX, "%s.%s", key_prefix, k);
            k += len + 1;
            len = get_config(pal_state.root_config, key, uri, CONFIG_MAX);
            if (len > 0) {
                if (!strstartswith_static(uri, FILE_URI_PREFIX)) {
                    SGX_DBG(DBG_E, "Invalid URI [%s]: Protected files must start with 'file:'\n",
                            uri);
                } else {
                    register_protected_path(uri, NULL);
                }
            }
        }
    } else {
        ret = nuris;
        goto out;
    }

    ret = 0;
out:
    free(cfgbuf);
    return ret;
}

/* Initialize the PF library, register PFs from the manifest */
int init_protected_files() {
    pf_set_callbacks(cb_malloc, free, cb_read, cb_write, cb_truncate, cb_flush, cb_open, cb_close,
                     cb_delete,
#ifdef DEBUG
                     cb_debug
#else
                     NULL
#endif
                     );

    pf_set_crypto_callbacks(cb_crypto_aes_gcm_encrypt, cb_crypto_aes_gcm_decrypt,
                            cb_crypto_random);

    /* TODO: development only: get SECRET WRAP KEY FOR PROTECTED FILES from manifest
       In the future, this key should be provisioned after local/remote attestation. */

    char key_hex[PF_KEY_SIZE * 2 + 1];
    ssize_t len = get_config(pal_state.root_config, "sgx.protected_files_key", key_hex,
                             sizeof(key_hex));
    if (len <= 0) {
        SGX_DBG(DBG_E, "*** No protected files wrap key specified in the manifest. "
                "Protected files will not be available. ***\n");
        return 0;
    }

    if (len != sizeof(key_hex) - 1) {
        SGX_DBG(DBG_E, "Malformed sgx.protected_files_key value in the manifest\n");
        return -PAL_ERROR_INVAL;
    }

    memset(g_pf_wrap_key, 0, sizeof(g_pf_wrap_key));
    for (ssize_t i = 0; i < len; i++) {
        int8_t val = hex2dec(key_hex[i]);
        if (val < 0) {
            SGX_DBG(DBG_E, "Malformed sgx.protected_files_key value in the manifest\n");
            return -PAL_ERROR_INVAL;
        }
        g_pf_wrap_key[i/2] = g_pf_wrap_key[i/2] * 16 + (uint8_t)val;
    }

    if (register_protected_files("sgx.protected_files") < 0)
        SGX_DBG(DBG_E, "sgx.protected_files key not found in manifest, "
                "protected files will not be available\n");

    return 0;
}

/* Open/create a PF */
static int open_protected_file(const char* path, struct protected_file* pf, pf_handle_t handle,
                               size_t size, pf_file_mode_t mode, bool create) {
    pf_status_t pfs;
    /* TODO: enable_recovery is always false for now */
    pfs = pf_open(handle, path, size, mode, create, false, &g_pf_wrap_key, &pf->context);
    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "pf_open(%d, %s) failed: %d\n", *(int*)handle, path, pfs);
        return -PAL_ERROR_DENIED;
    }
    return 0;
}

/* Prepare a PF for I/O
   This function registers the PF if path is in a registered PF directory, then
   calls the appropriate PF function to open/create it (if allowed) */
struct protected_file* load_protected_file(const char* path, int* fd, size_t size,
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
            if (ret != 0)
                return NULL;
        } else {
            SGX_DBG(DBG_D, "load_protected_file: %s, fd %d: returning old PF %p\n", path, *fd, pf);
        }
    }

    return pf;
}

/* Flush PF map buffers and optionally remove them.
   If pf is NULL, process all maps containing given buffer.
   If buffer is NULL, process all maps for given pf. */
int flush_pf_maps(struct protected_file* pf, void* buffer, bool remove) {
    struct pf_map* map;
    struct pf_map* tmp;
    size_t pf_size;
    pf_status_t pfs;

    SGX_DBG(DBG_D, "flush_pf_maps: pf %p, buf %p, remove %d\n", pf, buffer, remove);
    assert(pf || buffer);

    LISTP_FOR_EACH_ENTRY_SAFE(map, tmp, &g_pf_map_list, list) {
        if (pf && map->pf != pf)
            continue;

        if (buffer && map->buffer != buffer)
            continue;

        size_t size = map->size;

        if (!pf)
            pf = map->pf;

        pfs = pf_get_size(pf->context, &pf_size);
        assert(PF_SUCCESS(pfs));

        SGX_DBG(DBG_D, "flush_pf_maps: pf %p, buf %p, size %lu, offset %lu\n",
            map->pf, map->buffer, size, map->offset);

        assert(pf_size >= map->offset);
        if (map->offset + size > pf_size)
            size = pf_size - map->offset;

        if (size > 0) {
            pfs = pf_write(pf->context, map->offset, size, map->buffer);
            if (PF_FAILURE(pfs)) {
                SGX_DBG(DBG_E, "flush_pf_maps: pf_write failed: %d\n", pfs);
                return -PAL_ERROR_INVAL;
            }
        }

        if (remove)
            LISTP_DEL(map, &g_pf_map_list, list);
     }
    return 0;
}

/* Flush map buffers and unload/close the PF */
int unload_protected_file(struct protected_file* pf) {
    /* flush all pf's maps and delete them */
    int ret = flush_pf_maps(pf, NULL, true);
    if (ret < 0)
        return ret;
    __attribute__((unused)) pf_status_t pfs = pf_close(pf->context);
    assert(PF_SUCCESS(pfs));

    pf->context = NULL;
    return 0;
}
