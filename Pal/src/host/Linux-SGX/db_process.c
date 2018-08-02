/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
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

/*
 * db_process.c
 *
 * This source file contains functions to create a child process and terminate
 * the running process. Child does not inherit any objects or memory from its
 * parent pricess. A Parent process may not modify the execution of its
 * children. It can wait for a child to exit using its handle. Also, parent and
 * child may communicate through I/O streams provided by the parent to the child
 * at creation.
 */

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_crypto.h"
#include "api.h"

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>

DEFINE_LIST(trusted_child);
struct trusted_child {
    LIST_TYPE(trusted_child) list;
    sgx_arch_hash_t mrenclave;
    char uri[];
};

DEFINE_LISTP(trusted_child);
static LISTP_TYPE(trusted_child) trusted_children = LISTP_INIT;
static struct spinlock trusted_children_lock = LOCK_INIT;

int register_trusted_child(const char * uri, const char * mrenclave_str)
{
    struct trusted_child * tc = NULL, * new;
    int uri_len = strlen(uri);

    _DkSpinLock(&trusted_children_lock);

    listp_for_each_entry(tc, &trusted_children, list) {
        if (!memcmp(tc->uri, uri, uri_len + 1)) {
            _DkSpinUnlock(&trusted_children_lock);
            return 0;
        }
    }
    _DkSpinUnlock(&trusted_children_lock);

    new = malloc(sizeof(struct trusted_child) + uri_len);
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    memcpy(new->uri, uri, uri_len + 1);

    char mrenclave_text[sizeof(sgx_arch_hash_t) * 2 + 1] = "\0";
    int nbytes = 0;
    for (; nbytes < sizeof(sgx_arch_hash_t) ; nbytes++) {
        char byte1 = mrenclave_str[nbytes * 2];
        char byte2 = mrenclave_str[nbytes * 2 + 1];
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

        new->mrenclave[nbytes] = val;
        snprintf(mrenclave_text + nbytes * 2, 3, "%02x", val);
    }

    if (nbytes < sizeof(sgx_arch_hash_t)) {
        free(new);
        return -PAL_ERROR_INVAL;
    }

    SGX_DBG(DBG_S, "trusted: %s %s\n", mrenclave_text, new->uri);

    _DkSpinLock(&trusted_children_lock);

    listp_for_each_entry(tc, &trusted_children, list) {
        if (!memcmp(tc->uri, uri, uri_len + 1)) {
            _DkSpinUnlock(&trusted_children_lock);
            free(new);
            return 0;
        }
    }

    listp_add_tail(new, &trusted_children, list);
    _DkSpinUnlock(&trusted_children_lock);
    return 0;
}

struct proc_attestation_data {
    sgx_arch_mac_t  keyhash_mac;
    uint8_t         reserved[PAL_ATTESTATION_DATA_SIZE - sizeof(sgx_arch_mac_t)];
} __attribute__((packed));

struct check_child_param {
    PAL_MAC_KEY     mac_key;
    const char *    uri;
};

static int check_child_mrenclave (sgx_arch_hash_t * mrenclave,
                                  void * signed_data, void * check_param)
{
    struct pal_enclave_state * remote_state = signed_data;
    struct proc_attestation_data * data = (void *) &remote_state->data;

    /* the process must be a clean process */
    if (remote_state->enclave_flags & PAL_ENCLAVE_INITIALIZED)
        return 1;

    struct check_child_param * param = check_param;

    /* must make sure the signer of the report is also the owner of the key,
       in order to prevent man-in-the-middle attack */
    struct proc_attestation_data check_data;
    memset(&check_data, 0, sizeof(struct proc_attestation_data));

    lib_AESCMAC((void *) &param->mac_key, AES_CMAC_KEY_LEN,
                remote_state->enclave_identifier,
                sizeof(remote_state->enclave_identifier),
                check_data.keyhash_mac, sizeof(check_data.keyhash_mac));

    if (memcmp(data, &check_data, sizeof(struct proc_attestation_data)))
        return 1;

    /* always accept our own as child */
    if (!memcmp(mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t))) {
        SGX_DBG(DBG_S, "trusted child: <forked>\n");
        return 0;
    }

    struct trusted_child * tc;
    _DkSpinLock(&trusted_children_lock);

    listp_for_each_entry(tc, &trusted_children, list) {
        if (!memcmp(mrenclave, tc->mrenclave, sizeof(sgx_arch_hash_t))) {
            _DkSpinUnlock(&trusted_children_lock);
            SGX_DBG(DBG_S, "trusted child: %s\n", tc->uri);
            return 0;
        }
    }

    _DkSpinUnlock(&trusted_children_lock);
    return 1;
}

int _DkProcessCreate (PAL_HANDLE * handle, const char * uri,
                      int flags, const char ** args)
{
    /* only access creating process with regular file */
    if (!strpartcmp_static(uri, "file:"))
        return -PAL_ERROR_INVAL;

    unsigned int child_pid;
    int proc_fds[3];
    int nargs = 0, ret;

    if (args)
        for (const char ** a = args ; *a ; a++)
            nargs++;

    ret = ocall_create_process(uri, nargs, args,
                               proc_fds,
                               &child_pid);
    if (ret < 0)
        return ret;

    PAL_HANDLE proc = malloc(HANDLE_SIZE(process));
    SET_HANDLE_TYPE(proc, process);
    HANDLE_HDR(proc)->flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    proc->process.stream_in  = proc_fds[0];
    proc->process.stream_out = proc_fds[1];
    proc->process.cargo      = proc_fds[2];
    proc->process.pid = child_pid;
    proc->process.nonblocking = PAL_FALSE;

    PAL_SESSION_KEY session_key;
    ret = _DkStreamKeyExchange(proc, &session_key);
    if (ret < 0)
        return ret;

    struct check_child_param param;
    session_key_to_mac_key(&session_key, &param.mac_key);
    param.uri = uri;

    struct proc_attestation_data data;
    memset(&data, 0, sizeof(struct proc_attestation_data));

    lib_AESCMAC((void *) &param.mac_key, AES_CMAC_KEY_LEN,
                pal_enclave_state.enclave_identifier,
                sizeof(pal_enclave_state.enclave_identifier),
                data.keyhash_mac, sizeof(data.keyhash_mac));

    SGX_DBG(DBG_P|DBG_S, "Attestation data: %s\n",
            alloca_bytes2hexstr(data.keyhash_mac));

    ret = _DkStreamAttestationRequest(proc, &data,
                                      &check_child_mrenclave, &param);
    if (ret < 0)
        return ret;

    *handle = proc;
    return 0;
}

struct check_parent_param {
    PAL_MAC_KEY     mac_key;
};

static int check_parent_mrenclave (sgx_arch_hash_t * mrenclave,
                                   void * signed_data, void * check_param)
{
    struct pal_enclave_state * remote_state = signed_data;
    struct proc_attestation_param * data = (void *) &remote_state->data;

    struct check_parent_param * param = check_param;

    /* must make sure the signer of the report is also the owner of the key,
       in order to prevent man-in-the-middle attack */
    struct proc_attestation_data check_data;
    memset(&check_data, 0, sizeof(struct proc_attestation_data));

    lib_AESCMAC((void *) &param->mac_key, AES_CMAC_KEY_LEN,
                remote_state->enclave_identifier,
                sizeof(remote_state->enclave_identifier),
                check_data.keyhash_mac, sizeof(check_data.keyhash_mac));

    if (memcmp(data, &check_data, sizeof(struct proc_attestation_data)))
        return 1;

    /* for now, we will accept any enclave as a parent, but eventually
       we should check parent, maybe using crypto challenge */
    return 0;
}

int init_child_process (PAL_HANDLE * parent_handle)
{
    PAL_HANDLE parent = malloc(HANDLE_SIZE(process));
    SET_HANDLE_TYPE(parent, process);
    HANDLE_HDR(parent)->flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);

    parent->process.stream_in  = pal_sec.proc_fds[0];
    parent->process.stream_out = pal_sec.proc_fds[1];
    parent->process.cargo      = pal_sec.proc_fds[2];
    parent->process.pid        = pal_sec.ppid;
    parent->process.nonblocking = PAL_FALSE;

    PAL_SESSION_KEY session_key;
    int ret = _DkStreamKeyExchange(parent, &session_key);
    if (ret < 0)
        return ret;

    struct check_parent_param param;
    session_key_to_mac_key(&session_key, &param.mac_key);

    struct proc_attestation_data data;
    memset(&data, 0, sizeof(struct proc_attestation_data));

    lib_AESCMAC((void *) &param.mac_key, AES_CMAC_KEY_LEN,
                pal_enclave_state.enclave_identifier,
                sizeof(pal_enclave_state.enclave_identifier),
                data.keyhash_mac, sizeof(data.keyhash_mac));

    SGX_DBG(DBG_P|DBG_S, "Attestation data: %s\n",
            alloca_bytes2hexstr(data.keyhash_mac));

    ret = _DkStreamAttestationRespond(parent, &data,
                                      &check_parent_mrenclave,
                                      &param);
    if (ret < 0)
        return ret;

    *parent_handle = parent;
    return 0;
}

void print_alloced_pages (void);

void _DkProcessExit (int exitcode)
{
#if PRINT_ENCLAVE_STAT
    print_alloced_pages();
#endif
    if (exitcode)
        SGX_DBG(DBG_I, "DkProcessExit: Returning exit code %d\n", exitcode);
    ocall_exit(exitcode);
}

int _DkProcessSandboxCreate (const char * manifest, int flags)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t proc_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                          void * buffer)
{
    if (count >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    return ocall_read(handle->process.stream_in, buffer, count);
}

static int64_t proc_write (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                           const void * buffer)
{
    if (count >= (1ULL << (sizeof(unsigned int) * 8)))
        return -PAL_ERROR_INVAL;

    int bytes = ocall_write(handle->process.stream_out, buffer, count);

    if (bytes == -PAL_ERROR_TRYAGAIN)
        HANDLE_HDR(handle)->flags &= ~WRITEABLE(1);

    if (bytes < 0)
        return bytes;

    if (bytes == count)
        HANDLE_HDR(handle)->flags |= WRITEABLE(1);
    else
        HANDLE_HDR(handle)->flags &= ~WRITEABLE(1);

    return bytes;
}

static int proc_close (PAL_HANDLE handle)
{
    if (handle->process.stream_in != PAL_IDX_POISON) {
        ocall_close(handle->process.stream_in);
        handle->process.stream_in = PAL_IDX_POISON;
    }

    if (handle->process.stream_out != PAL_IDX_POISON) {
        ocall_close(handle->process.stream_out);
        handle->process.stream_out = PAL_IDX_POISON;
    }

    if (handle->process.cargo != PAL_IDX_POISON) {
        ocall_close(handle->process.cargo);
        handle->process.cargo = PAL_IDX_POISON;
    }

    return 0;
}

static int proc_delete (PAL_HANDLE handle, int access)
{
    int shutdown;
    switch (access) {
        case 0:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_RD:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WR:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (access != PAL_DELETE_WR &&
        handle->process.stream_in != PAL_IDX_POISON) {
        ocall_close(handle->process.stream_in);
        handle->process.stream_in = PAL_IDX_POISON;
    }

    if (access != PAL_DELETE_RD &&
        handle->process.stream_out != PAL_IDX_POISON) {
        ocall_close(handle->process.stream_out);
        handle->process.stream_out = PAL_IDX_POISON;
    }

    if (handle->process.cargo != PAL_IDX_POISON)
        ocall_sock_shutdown(handle->process.cargo, shutdown);

    return 0;
}

static int proc_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->process.stream_in == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret = ocall_fionread(handle->process.stream_in);

    if (ret < 0)
        return -ret;

    memset(attr, 0, sizeof(PAL_STREAM_ATTR));
    attr->pending_size = ret;
    attr->disconnected = HANDLE_HDR(handle)->flags & (ERROR(0)|ERROR(1));
    attr->readable = (attr->pending_size > 0);
    attr->writeable = HANDLE_HDR(handle)->flags & WRITEABLE(1);
    attr->nonblocking = handle->process.nonblocking;
    return 0;
}

static int proc_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->process.stream_in == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    if (attr->nonblocking != handle->process.nonblocking) {
        int ret = ocall_fsetnonblock(handle->process.stream_in,
                                     handle->process.nonblocking);

        if (ret < 0)
            return ret;

        handle->process.nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops proc_ops = {
        .read           = &proc_read,
        .write          = &proc_write,
        .close          = &proc_close,
        .delete         = &proc_delete,
        .attrquerybyhdl = &proc_attrquerybyhdl,
        .attrsetbyhdl   = &proc_attrsetbyhdl,
    };
