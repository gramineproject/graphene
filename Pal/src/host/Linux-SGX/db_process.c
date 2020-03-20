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
#include "pal_linux_error.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_crypto.h"
#include "spinlock.h"
#include "api.h"

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
typedef __kernel_pid_t pid_t;
#include <asm/fcntl.h>

DEFINE_LIST(trusted_child);
struct trusted_child {
    LIST_TYPE(trusted_child) list;
    sgx_measurement_t mr_enclave;
    char uri[];
};

DEFINE_LISTP(trusted_child);
static LISTP_TYPE(trusted_child) trusted_children = LISTP_INIT;
static spinlock_t trusted_children_lock = INIT_SPINLOCK_UNLOCKED;

int register_trusted_child(const char * uri, const char * mr_enclave_str)
{
    struct trusted_child * tc = NULL, * new;
    int uri_len = strlen(uri);

    spinlock_lock(&trusted_children_lock);

    LISTP_FOR_EACH_ENTRY(tc, &trusted_children, list) {
        if (!memcmp(tc->uri, uri, uri_len + 1)) {
            spinlock_unlock(&trusted_children_lock);
            return 0;
        }
    }
    spinlock_unlock(&trusted_children_lock);

    new = malloc(sizeof(struct trusted_child) + uri_len);
    if (!new)
        return -PAL_ERROR_NOMEM;

    INIT_LIST_HEAD(new, list);
    memcpy(new->uri, uri, uri_len + 1);

    char mr_enclave_text[sizeof(sgx_measurement_t) * 2 + 1] = "\0";
    size_t nbytes = 0;
    for (; nbytes < sizeof(sgx_measurement_t) ; nbytes++) {
        char byte1 = mr_enclave_str[nbytes * 2];
        char byte2 = mr_enclave_str[nbytes * 2 + 1];
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

        new->mr_enclave.m[nbytes] = val;
        snprintf(mr_enclave_text + nbytes * 2, 3, "%02x", val);
    }

    if (nbytes < sizeof(sgx_measurement_t)) {
        free(new);
        return -PAL_ERROR_INVAL;
    }

    SGX_DBG(DBG_S, "trusted: %s %s\n", mr_enclave_text, new->uri);

    spinlock_lock(&trusted_children_lock);

    LISTP_FOR_EACH_ENTRY(tc, &trusted_children, list) {
        if (!memcmp(tc->uri, uri, uri_len + 1)) {
            spinlock_unlock(&trusted_children_lock);
            free(new);
            return 0;
        }
    }

    LISTP_ADD_TAIL(new, &trusted_children, list);
    spinlock_unlock(&trusted_children_lock);
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
 *       See the implementation in check_child_mr_enclave() and check_parent_mr_enclave().
 *       For a child process, we check if the child's mr_enclave is listed as
 *       "sgx.trusted_children.xxx = ..." in the manifest.
 *       For a parent process, we currently don't check its mr_enclave in the child.
 *       This is a limitation because listing the parent's mr_enclave in the child's
 *       manifest will change the child's mr_enclave, which then needs to be updated
 *       in the parent's manifest, and eventually falls into a loop of updating both
 *       manifest files.
 *
 * (4) The two parties who create the session key need to be the ones proven by the CPU
 *     (for preventing man-in-the-middle attacks).
 *
 *       See the implementation in check_child_mr_enclave() and check_parent_mr_enclave().
 *       The local reports from both sides will contain a MAC, generated by hashing
 *       the unique enclave ID (a 64-bit integer) using AES-CMAC with the session key.
 *       Because both the enclave ID and the session key are randomly created for each
 *       enclave, no report can be reused even from an enclave with the same mr_enclave.
 */

struct proc_data {
    sgx_mac_t eid_mac;
};

static int generate_sign_data(const PAL_SESSION_KEY* session_key, uint64_t enclave_id,
                              sgx_sign_data_t* sign_data) {
    struct proc_data data;
    int ret = lib_AESCMAC((uint8_t*)session_key,   sizeof(*session_key),
                          (uint8_t*)&enclave_id,   sizeof(enclave_id),
                          (uint8_t*)&data.eid_mac, sizeof(data.eid_mac));
    if (ret < 0)
        return ret;

    SGX_DBG(DBG_P|DBG_S, "Enclave identifier: %016lx -> %s\n", enclave_id,
            ALLOCA_BYTES2HEXSTR(data.eid_mac));

    /* Copy proc_data into sgx_sign_data_t */
    assert(sizeof(data) <= sizeof(*sign_data));
    memset(sign_data, 0, sizeof(*sign_data));
    memcpy(sign_data, &data, sizeof(data));
    return 0;
}

static int check_child_mr_enclave(PAL_HANDLE child, sgx_measurement_t* mr_enclave,
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

    /* Always accept the same mr_enclave as child process */
    if (!memcmp(mr_enclave, &pal_sec.mr_enclave, sizeof(sgx_measurement_t))) {
        SGX_DBG(DBG_S, "trusted child: <forked>\n");
        return 0;
    }

    struct trusted_child * tc;
    spinlock_lock(&trusted_children_lock);

    /* Try to find a matching mr_enclave from the manifest */
    LISTP_FOR_EACH_ENTRY(tc, &trusted_children, list) {
        if (!memcmp(mr_enclave, &tc->mr_enclave, sizeof(sgx_measurement_t))) {
            spinlock_unlock(&trusted_children_lock);
            SGX_DBG(DBG_S, "trusted child: %s\n", tc->uri);
            return 0;
        }
    }

    spinlock_unlock(&trusted_children_lock);
    return 1;
}

int _DkProcessCreate (PAL_HANDLE * handle, const char * uri, const char ** args)
{
    /* only access creating process with regular file */
    if (!strstartswith_static(uri, URI_PREFIX_FILE))
        return -PAL_ERROR_INVAL;

    unsigned int child_pid;
    int stream_fd;
    int nargs = 0, ret;

    if (args)
        for (const char ** a = args ; *a ; a++)
            nargs++;

    ret = ocall_create_process(uri, nargs, args, &stream_fd, &child_pid);
    if (ret < 0)
        return ret;

    PAL_HANDLE child = malloc(HANDLE_SIZE(process));
    SET_HANDLE_TYPE(child, process);
    HANDLE_HDR(child)->flags |= RFD(0)|WFD(0);
    child->process.stream      = stream_fd;
    child->process.pid         = child_pid;
    child->process.nonblocking = PAL_FALSE;
    child->process.ssl_ctx     = NULL;

    ret = _DkStreamKeyExchange(child, &child->process.session_key);
    if (ret < 0)
        goto failed;

    sgx_sign_data_t sign_data;
    ret = generate_sign_data(&child->process.session_key, pal_enclave_state.enclave_id,
                             &sign_data);
    if (ret < 0)
        goto failed;

    ret = _DkStreamReportRequest(child, &sign_data, &check_child_mr_enclave);
    if (ret < 0)
        goto failed;

    ret = _DkStreamSecureInit(child, /*is_server=*/true, &child->process.session_key,
                              (LIB_SSL_CONTEXT**)&child->process.ssl_ctx);
    if (ret < 0)
        goto failed;

    *handle = child;
    return 0;

failed:
    free(child);
    return ret;
}

static int check_parent_mr_enclave(PAL_HANDLE parent, sgx_measurement_t* mr_enclave,
                                   struct pal_enclave_state* remote_state) {
    __UNUSED(mr_enclave);
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
    HANDLE_HDR(parent)->flags |= RFD(0)|WFD(0);

    parent->process.stream      = pal_sec.stream_fd;
    parent->process.pid         = pal_sec.ppid;
    parent->process.nonblocking = PAL_FALSE;
    parent->process.ssl_ctx     = NULL;

    int ret = _DkStreamKeyExchange(parent, &parent->process.session_key);
    if (ret < 0)
        return ret;

    sgx_sign_data_t sign_data;
    ret = generate_sign_data(&parent->process.session_key, pal_enclave_state.enclave_id,
                             &sign_data);
    if (ret < 0)
        return ret;

    ret = _DkStreamReportRespond(parent, &sign_data, &check_parent_mr_enclave);
    if (ret < 0)
        return ret;

    ret = _DkStreamSecureInit(parent, /*is_server=*/false, &parent->process.session_key,
                              (LIB_SSL_CONTEXT**)&parent->process.ssl_ctx);
    if (ret < 0)
        return ret;

    *parent_handle = parent;
    return 0;
}

void print_alloced_pages (void);

noreturn void _DkProcessExit (int exitcode)
{
#if PRINT_ENCLAVE_STAT
    print_alloced_pages();
#endif
    if (exitcode)
        SGX_DBG(DBG_I, "DkProcessExit: Returning exit code %d\n", exitcode);
    ocall_exit(exitcode, /*is_exitgroup=*/true);
    while (true) {
        /* nothing */;
    }
}

static int64_t proc_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                          void * buffer)
{
    if (offset)
        return -PAL_ERROR_INVAL;

    if (count != (uint32_t)count)
        return -PAL_ERROR_INVAL;

    ssize_t bytes;
    if (handle->process.ssl_ctx) {
        bytes = _DkStreamSecureRead(handle->process.ssl_ctx, buffer, count);
    } else {
        bytes = ocall_read(handle->process.stream, buffer, count);
        bytes = IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
    }

    return bytes;
}

static int64_t proc_write (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                           const void * buffer)
{
    if (offset)
        return -PAL_ERROR_INVAL;

    if (count != (uint32_t)count)
        return -PAL_ERROR_INVAL;

    ssize_t bytes;
    if (handle->process.ssl_ctx) {
        bytes = _DkStreamSecureWrite(handle->process.ssl_ctx, buffer, count);
    } else {
        bytes = ocall_write(handle->process.stream, buffer, count);
        bytes = IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
    }

    return bytes;
}

static int proc_close (PAL_HANDLE handle)
{
    if (handle->process.stream != PAL_IDX_POISON) {
        ocall_close(handle->process.stream);
        handle->process.stream = PAL_IDX_POISON;
    }

    if (handle->process.ssl_ctx) {
        _DkStreamSecureFree((LIB_SSL_CONTEXT*)handle->process.ssl_ctx);
        handle->process.ssl_ctx = NULL;
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

    if (handle->process.stream != PAL_IDX_POISON)
        ocall_shutdown(handle->process.stream, shutdown);

    return 0;
}

static int proc_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;

    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = HANDLE_HDR(handle)->type;
    attr->nonblocking  = handle->process.nonblocking;
    attr->disconnected = HANDLE_HDR(handle)->flags & ERROR(0);
    attr->secure = handle->process.ssl_ctx ? PAL_TRUE : PAL_FALSE;

    /* get number of bytes available for reading */
    ret = ocall_fionread(handle->process.stream);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->pending_size = ret;

    /* query if there is data available for reading */
    struct pollfd pfd = {.fd = handle->process.stream, .events = POLLIN | POLLOUT, .revents = 0};
    ret = ocall_poll(&pfd, 1, 0);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->readable = ret == 1 && (pfd.revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
    attr->writable = ret == 1 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    return 0;
}

static int proc_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    if (attr->nonblocking != handle->process.nonblocking) {
        int ret = ocall_fsetnonblock(handle->process.stream,
                                     handle->process.nonblocking);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->process.nonblocking = attr->nonblocking;
    }

    if (!attr->secure && handle->process.ssl_ctx) {
        /* remove TLS protection from process.stream */
        _DkStreamSecureFree((LIB_SSL_CONTEXT*)handle->process.ssl_ctx);
        handle->process.ssl_ctx = NULL;
    } else if (attr->secure && !handle->process.ssl_ctx) {
        /* adding TLS protection for process.stream is not yet implemented */
        SGX_DBG(DBG_E, "Securing a non-secure process handle is not supported!\n");
        return -PAL_ERROR_NOTSUPPORT;
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
