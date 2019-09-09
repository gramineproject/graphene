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

/*
 * For SGX, the creation of a child process requires a clean enclave and a secure channel
 * between the parent and child processes (enclaves). The establishment of the secure
 * channel must be resilient to a host-level, root-privilege adversary. Such an adversary
 * can either create arbitrary enclaves, or intercept the handshake protocol between the
 * parent and child enclaves to launch a man-in-the-middle attack.
 *
 * Prerequisites of a secure channel:
 * (1) A session key needs to be shared only between the parent and child enclaves.
 *
 *       See the implementation in _DkStreamKeyExchange().
 *       When initializing an RPC stream, both ends of the stream needs to use
 *       Diffie-Hellman to exchange a session key. The key will be used to both identify
 *       the connection (to prevent man-in-the-middle attack) and for future encryption.
 *
 * (2) Both the parent and child enclaves need to be proven by the Intel CPU.
 *
 *       See the implementation in _DkStreamReportRequest() and _DkStreamReportRespond().
 *       The two ends of the RPC stream need to exchange local attestation reports
 *       signed by the Intel CPUs to prove themselves to be running inside enclaves
 *       on the same platform. The local attestation reports contain no secret information
 *       and can be verified cryptographically, and can be sent on an unencrypted channel.
 *
 *       The flow of local attestation is as follows:
 *         - Parent: Send targetinfo(Parent) to Child
 *         - Child:  Generate report(Child -> Parent) and send to Parent
 *         - Parent: Verify report(Child -> Parent)
 *         - Parent: Extract targetinfo(Child) from report(Child -> Parent)
 *                   and then generate report(Parent -> Child)
 *         - Child:  Verify report(Parent -> Child)
 *
 * (3) Both the parent and child enclaves need to have a white-listed measurement.
 *
 *       See the implementation in check_child_mrenclave() and check_parent_mrenclave().
 *       For a child process, we check if the child's mrenclave is listed as
 *       "sgx.trusted_children.xxx = ..." in the manifest.
 *       For a parent process, we currently don't check its mrenclave in the child.
 *       This is a limitation because listing the parent's mrenclave in the child's
 *       manifest will change the child's mrenclave, which then needs to be updated
 *       in the parent's manifest, and eventually falls into a loop of updating both
 *       manifest files.
 *
 * (4) The two parties who create the session key need to be the ones proven by the CPU
 *     (for preventing man-in-the-middle attacks).
 *
 *       See the implementation in check_child_mrenclave() and check_parent_mrenclave().
 *       The local reports from both sides will contain a MAC, generated by hashing
 *       the unique enclave ID (a 64-bit integer) using AES-CMAC with the session key.
 *       Because both the enclave ID and the session key are randomly created for each
 *       enclave, no report can be reused even from an enclave with the same mrenclave.
 */

struct proc_data {
    sgx_arch_mac_t eid_mac;
};

static int generate_sign_data(const PAL_SESSION_KEY* session_key, uint64_t enclave_id,
                              sgx_sign_data_t* sign_data) {
    struct proc_data data;
    int ret = lib_AESCMAC((uint8_t*)session_key,   sizeof(*session_key),
                          (uint8_t*)&enclave_id,   sizeof(enclave_id),
                          (uint8_t*)&data.eid_mac, sizeof(data.eid_mac));
    if (ret < 0)
        return ret;

    SGX_DBG(DBG_P|DBG_S, "Enclave identifier: %016llx -> %s\n", enclave_id,
            alloca_bytes2hexstr(data.eid_mac));

    /* Copy proc_data into sgx_sign_data_t */
    assert(sizeof(data) <= sizeof(*sign_data));
    memset(sign_data, 0, sizeof(*sign_data));
    memcpy(sign_data, &data, sizeof(data));
    return 0;
}

static int check_child_mrenclave(PAL_HANDLE child, sgx_arch_hash_t* mrenclave,
                                 struct pal_enclave_state* remote_state) {
    /* the process must be a clean process */
    if (remote_state->enclave_flags & PAL_ENCLAVE_INITIALIZED)
        return 1;

    sgx_sign_data_t sign_data;
    int ret = generate_sign_data(&child->process.session_key, remote_state->enclave_id,
                                 &sign_data);
    if (ret < 0)
        return ret;

    /* must make sure the signer of the report is also the owner of the key,
       in order to prevent man-in-the-middle attack */
    if (memcmp(&remote_state->enclave_data, &sign_data, sizeof(sign_data)))
        return 1;

    /* Always accept the same mrenclave as child process */
    if (!memcmp(mrenclave, pal_sec.mrenclave, sizeof(sgx_arch_hash_t))) {
        SGX_DBG(DBG_S, "trusted child: <forked>\n");
        return 0;
    }

    struct trusted_child * tc;
    _DkSpinLock(&trusted_children_lock);

    /* Try to find a matching mrenclave from the manifest */
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

    ret = ocall_create_process(uri, nargs, args, proc_fds, &child_pid);
    if (ret < 0)
        return ret;

    PAL_HANDLE child = malloc(HANDLE_SIZE(process));
    SET_HANDLE_TYPE(child, process);
    HANDLE_HDR(child)->flags |= RFD(0)|WFD(1)|RFD(2)|WFD(2)|WRITEABLE(1)|WRITEABLE(2);
    child->process.stream_in  = proc_fds[0];
    child->process.stream_out = proc_fds[1];
    child->process.cargo      = proc_fds[2];
    child->process.pid = child_pid;
    child->process.nonblocking = PAL_FALSE;

    ret = _DkStreamKeyExchange(child, &child->process.session_key);
    if (ret < 0)
        goto failed;

    sgx_sign_data_t sign_data;
    ret = generate_sign_data(&child->process.session_key, pal_enclave_state.enclave_id,
                             &sign_data);
    if (ret < 0)
        goto failed;

    ret = _DkStreamReportRequest(child, &sign_data, &check_child_mrenclave);
    if (ret < 0)
        goto failed;

    *handle = child;
    return 0;

failed:
    free(child);
    return ret;
}

static int check_parent_mrenclave(PAL_HANDLE parent, sgx_arch_hash_t* mrenclave,
                                  struct pal_enclave_state* remote_state) {
    sgx_sign_data_t sign_data;
    int ret = generate_sign_data(&parent->process.session_key, remote_state->enclave_id,
                                 &sign_data);
    if (ret < 0)
        return ret;

    if (memcmp(&remote_state->enclave_data, &sign_data, sizeof(sign_data)))
        return 1;

    /* XXX: For now, accept any enclave, but eventually should challenge the parent process */
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

    int ret = _DkStreamKeyExchange(parent, &parent->process.session_key);
    if (ret < 0)
        return ret;

    sgx_sign_data_t sign_data;
    ret = generate_sign_data(&parent->process.session_key, pal_enclave_state.enclave_id,
                             &sign_data);
    if (ret < 0)
        return ret;

    ret = _DkStreamReportRespond(parent, &sign_data, &check_parent_mrenclave);
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
    ocall_exit();
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
