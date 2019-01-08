/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "enclave_ocalls.h"
#include "ocall_types.h"
#include "ecall_types.h"
#include <api.h>

#include <asm/errno.h>
#include <linux/futex.h>
#include "rpcqueue.h"

rpc_queue_t* g_rpc_queue;  /* pointer to untrusted queue */

static void* alloc_in_user(void* ptr, uint64_t size) {
    if (!sgx_is_within_enclave(ptr, size))
        return ptr;

    return sgx_ocalloc(size);
}

static void* copy_to_user(const void* ptr, uint64_t size) {
    if (!sgx_is_within_enclave(ptr, size))
        return (void*)ptr;

    void* tmp = sgx_ocalloc(size);
    memcpy(tmp, ptr, size);
    return tmp;
}

static void copy_from_user(void* ptr, const void* user_ptr, uint64_t size) {
    if (sgx_is_within_enclave(user_ptr, size) ||
            !sgx_is_within_enclave(ptr, size))
        return;

    memcpy(ptr, user_ptr, size);
}

static int sgx_exitless_ocall(int code, void* ms) {
    /* perform OCALL with enclave exit if no RPC queue */
    if (!g_rpc_queue)
        return sgx_ocall(code, ms);

    /* allocate request on OCALL stack; it is automatically freed on OCALL end;
     * note that request's lock is used in futex() and must be aligned to 4B
     * so we pad OCALL stack to 4B alignment with dummy chars */
    char* dummy;
    do {
        dummy = sgx_ocalloc(sizeof(*dummy));
    } while ((uint64_t)dummy % 4 != 0);

    rpc_request_t* req = sgx_ocalloc(sizeof(*req));
    req->ocall_index = code;
    req->buffer      = ms;
    atomic_set(&req->lock, REQ_LOCKED_NO_WAITERS);

    /* enqueue OCALL into RPC queue */
    req = rpc_enqueue(g_rpc_queue, req);
    if (!req) {
        /* no space in queue: all RPC threads are busy with outstanding ocalls */
        return -ENOMEM;
    }

    /* wait till request processing is finished; try spinlock first */
    int timedout = rpc_spin_lock_timeout(&req->lock, RPC_SPIN_LOCK_TIMEOUT);
    if (timedout) {
        /* OCALL takes a lot of time, so fallback to waiting on a futex;
         * note that at this point we exit the enclave to perform syscall;
         * this code is based on Mutex 2 from Futexes are Tricky */
        int c;
        if ((c = atomic_cmpxchg(&req->lock, REQ_UNLOCKED, REQ_LOCKED_NO_WAITERS))) {
            do {
                if (c == REQ_LOCKED_WITH_WAITERS ||
                    atomic_cmpxchg(&req->lock, REQ_LOCKED_NO_WAITERS, REQ_LOCKED_WITH_WAITERS)) {

                    /* allocate futex args on OCALL stack; automatically freed on OCALL end */
                    ms_ocall_futex_t * ms = sgx_ocalloc(sizeof(*ms));
                    ms->ms_futex = (int*)&req->lock.counter;
                    ms->ms_op = FUTEX_WAIT_PRIVATE;
                    ms->ms_val = REQ_LOCKED_WITH_WAITERS;
                    ms->ms_timeout = OCALL_NO_TIMEOUT;

                    int ret = sgx_ocall(OCALL_FUTEX, ms);
                    if (ret < 0 && ret != -PAL_ERROR_TRYAGAIN)
                        return -ENOMEM;
                }
            } while ((c = atomic_cmpxchg(&req->lock, REQ_UNLOCKED, REQ_LOCKED_WITH_WAITERS)));
        }
    }

    return req->result;
}

/* Adding new OCALLs (syscalls):
 *   1. Add new enum for OCALL (in ocall_types.h)
 *   2. Add new ms_ocall_*_t struct which captures all OCALL args (in ocall_types.h)
 *   3. Add new sgx_*() function which is executed in untrusted PAL and issues
 *      an actual syscall (in sgx_enclave.c)
 *   4. Register this sgx_*() function in ocall_table (in sgx_enclave.c)
 *   5. Add new ocall_*() function which is executed in trusted PAL and performs
 *      an OCALL into untrusted PAL to call sgx_*()
 *
 * For step (5), the pattern to write new ocall_*() function is:
 *
 * int ocall_new_syscall (void* arg1, void* arg2) {
 *    int retval = 0;
 *
 *    // get new stack frame on enclave thread's untrusted stack (OCALL stack)
 *    void* frame = sgx_ocget_frame();
 *
 *    // push struct with all OCALL args on current OCALL stack frame
 *    ms_ocall_new_syscall_t * ms = sgx_ocalloc(sizeof(*ms));
 *    ms->ms_arg1 = arg1;
 *    ms->ms_arg2 = arg2;
 *
 *    // perform exitless OCALL
 *    retval = sgx_exitless_ocall(OCALL_NEW_SYSCALL, ms);
 *
 *    // free (pop) current OCALL stack frame and return;
 *    // this automatically frees all args pushed on OCALL stack
 *    sgx_ocfree_frame(frame);
 *    return retval;
 * }
 *
 * Most new syscalls should use sgx_exitless_ocall() for performance reasons.
 * If new syscall _needs_ to perform enclave exit, replace with sgx_ocall().
 */

int ocall_exit(int exitcode)
{
    int retval = 0;
    int64_t code = exitcode;
    sgx_ocall(OCALL_EXIT, (void *) code);
    /* NOTREACHED */
    return retval;
}

int ocall_print_string (const char * str, unsigned int length)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    if (!str || length <= 0) {
        sgx_ocfree_frame(frame);
        return -PAL_ERROR_DENIED;
    }

    ms_ocall_print_string_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_str = copy_to_user(str, length);
    ms->ms_length = length;

    retval = sgx_exitless_ocall(OCALL_PRINT_STRING, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_alloc_untrusted (uint64_t size, void ** mem)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_alloc_untrusted_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_size = size;

    retval = sgx_exitless_ocall(OCALL_ALLOC_UNTRUSTED, ms);
    if (!retval) {
        if (sgx_is_within_enclave(ms->ms_mem, size)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }
        *mem = ms->ms_mem;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_map_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_map_untrusted_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = sgx_exitless_ocall(OCALL_MAP_UNTRUSTED, ms);
    if (!retval) {
        if (sgx_is_within_enclave(ms->ms_mem, size)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }
        *mem = ms->ms_mem;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_unmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    if (sgx_is_within_enclave(mem, size)) {
        sgx_ocfree_frame(frame);
        return -PAL_ERROR_INVAL;
    }

    ms_ocall_unmap_untrusted_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = sgx_exitless_ocall(OCALL_UNMAP_UNTRUSTED, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_cpuid_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_leaf = leaf;
    ms->ms_subleaf = subleaf;

    retval = sgx_exitless_ocall(OCALL_CPUID, ms);
    if (!retval) {
        values[0] = ms->ms_values[0];
        values[1] = ms->ms_values[1];
        values[2] = ms->ms_values[2];
        values[3] = ms->ms_values[3];
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int len = pathname ? strlen(pathname) + 1 : 0;

    ms_ocall_open_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_pathname = copy_to_user(pathname, len);
    ms->ms_flags = flags;
    ms->ms_mode = mode;

    retval = sgx_exitless_ocall(OCALL_OPEN, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_close_t *ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_CLOSE, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_read (int fd, void * buf, unsigned int count)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    void * obuf = NULL;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms_ocall_read_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = sgx_ocalloc(count);
    ms->ms_count = count;

    retval = sgx_exitless_ocall(OCALL_READ, ms);

    if (retval > 0)
        memcpy(buf, ms->ms_buf, retval);

    sgx_ocfree_frame(frame);

    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));

    return retval;
}

int ocall_write (int fd, const void * buf, unsigned int count)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    void * obuf = NULL;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms_ocall_write_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    if (obuf) {
        ms->ms_buf = obuf;
        memcpy(obuf, buf, count);
    } else {
        ms->ms_buf = copy_to_user(buf, count);
    }
    ms->ms_count = count;

    retval = sgx_exitless_ocall(OCALL_WRITE, ms);

    sgx_ocfree_frame(frame);

    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));

    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_fstat_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FSTAT, ms);
    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_fionread_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FIONREAD, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_fsetnonblock_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = sgx_exitless_ocall(OCALL_FSETNONBLOCK, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_fchmod_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = sgx_exitless_ocall(OCALL_FCHMOD, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_fsync_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FSYNC, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_ftruncate_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = sgx_exitless_ocall(OCALL_FTRUNCATE, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int len = pathname ? strlen(pathname) + 1 : 0;

    ms_ocall_mkdir_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_pathname = copy_to_user(pathname, len);
    ms->ms_mode = mode;

    retval = sgx_exitless_ocall(OCALL_MKDIR, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_getdents_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fd = fd;
    ms->ms_dirp = alloc_in_user(dirp, size);
    ms->ms_size = size;

    retval = sgx_exitless_ocall(OCALL_GETDENTS, ms);
    if (retval > 0)
        copy_from_user(dirp, ms->ms_dirp, retval);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_wake_thread (void * tcs)
{
    /* NOTE: since this can be executed from within signal handler and sends
     *       SIGCONT to other enclave threads, cannot use exitless here */
    return sgx_ocall(OCALL_WAKE_THREAD, tcs);
}

int ocall_create_process (const char * uri,
                          int nargs, const char ** args,
                          int procfds[3],
                          unsigned int * pid)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int ulen = uri ? strlen(uri) + 1 : 0;

    ms_ocall_create_process_t * ms = sgx_ocalloc(sizeof(*ms) + sizeof(char *) * nargs);
    ms->ms_uri = uri ? copy_to_user(uri, ulen) : NULL;
    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? copy_to_user(args[i], len) : NULL;
    }

    retval = sgx_exitless_ocall(OCALL_CREATE_PROCESS, ms);
    if (!retval) {
        if (pid)
            *pid = ms->ms_pid;
        procfds[0] = ms->ms_proc_fds[0];
        procfds[1] = ms->ms_proc_fds[1];
        procfds[2] = ms->ms_proc_fds[2];
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_futex (int * futex, int op, int val,
                 const uint64_t * timeout)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    if (sgx_is_within_enclave(futex, sizeof(int))) {
        sgx_ocfree_frame(frame);
        return -PAL_ERROR_INVAL;
    }

    ms_ocall_futex_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = sgx_exitless_ocall(OCALL_FUTEX, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_socketpair_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = sgx_exitless_ocall(OCALL_SOCKETPAIR, ms);
    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_listen (int domain, int type, int protocol,
                       struct sockaddr * addr, unsigned int * addrlen,
                       struct sockopt * sockopt)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    unsigned int bind_len = *addrlen;

    ms_ocall_sock_listen_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addr = copy_to_user(addr, bind_len);
    ms->ms_addrlen = bind_len;

    retval = sgx_exitless_ocall(OCALL_SOCK_LISTEN, ms);
    if (retval >= 0) {
        if (addrlen && (
            sgx_is_within_enclave(ms->ms_addr, bind_len) ||
            ms->ms_addrlen > bind_len)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }

        if (addr) {
            copy_from_user(addr, ms->ms_addr, ms->ms_addrlen);
            *addrlen = ms->ms_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    unsigned int len = addrlen ? *addrlen : 0;

    ms_ocall_sock_accept_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_addr = copy_to_user(addr, len);
    ms->ms_addrlen = len;

    retval = sgx_exitless_ocall(OCALL_SOCK_ACCEPT, ms);
    if (retval >= 0) {
        if (len && (sgx_is_within_enclave(ms->ms_addr, len) ||
                    ms->ms_addrlen > len)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }

        if (addr) {
            copy_from_user(addr, ms->ms_addr, ms->ms_addrlen);
            *addrlen = ms->ms_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_connect (int domain, int type, int protocol,
                        const struct sockaddr * addr,
                        unsigned int addrlen,
                        struct sockaddr * bind_addr,
                        unsigned int * bind_addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    unsigned int bind_len = bind_addrlen ? *bind_addrlen : 0;

    ms_ocall_sock_connect_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addr = copy_to_user(addr, addrlen);
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addr = bind_addr ? copy_to_user(bind_addr, bind_len) : NULL;
    ms->ms_bind_addrlen = bind_len;

    retval = sgx_exitless_ocall(OCALL_SOCK_CONNECT, ms);
    if (retval >= 0) {
        if (bind_len && (
            sgx_is_within_enclave(ms->ms_bind_addr, bind_len) ||
            ms->ms_bind_addrlen > bind_len)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }

        if (bind_addr) {
            copy_from_user(bind_addr, ms->ms_bind_addr,
                           ms->ms_bind_addrlen);
            *bind_addrlen = ms->ms_bind_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlen)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    unsigned int len = addrlen ? *addrlen : 0;

    ms_ocall_sock_recv_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_buf = alloc_in_user(buf, count);
    ms->ms_count = count;
    ms->ms_addr = addr ? alloc_in_user(addr, len) : NULL;
    ms->ms_addrlen = len;

    retval = sgx_exitless_ocall(OCALL_SOCK_RECV, ms);
    if (retval >= 0) {
        if (len && (sgx_is_within_enclave(ms->ms_addr, len) ||
                    ms->ms_addrlen > len)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }

        copy_from_user(buf, ms->ms_buf, retval);
        copy_from_user(addr, ms->ms_addr, ms->ms_addrlen);
        if (addrlen)
            *addrlen = ms->ms_addrlen;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sock_send_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_buf = copy_to_user(buf, count);
    ms->ms_count = count;
    ms->ms_addr = addr ? copy_to_user(addr, addrlen) : NULL;
    ms->ms_addrlen = addrlen;

    retval = sgx_exitless_ocall(OCALL_SOCK_SEND, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_recv_fd (int sockfd, void * buf, unsigned int count,
                        unsigned int * fds, unsigned int * nfds)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sock_recv_fd_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_buf = alloc_in_user(buf, count);
    ms->ms_count = count;
    ms->ms_fds = fds ? alloc_in_user(fds, sizeof(int) * (*nfds)) : NULL;
    ms->ms_nfds = *nfds;

    retval = sgx_exitless_ocall(OCALL_SOCK_RECV_FD, ms);
    if (retval >= 0) {
        if (sgx_is_within_enclave(ms->ms_fds, sizeof(int) * (*nfds)) ||
            ms->ms_nfds > (*nfds)) {
            sgx_ocfree_frame(frame);
            return -PAL_ERROR_DENIED;
        }

        copy_from_user(buf, ms->ms_buf, retval);
        copy_from_user(fds, ms->ms_fds, sizeof(int) * ms->ms_nfds);
        *nfds = ms->ms_nfds;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_send_fd (int sockfd, const void * buf, unsigned int count,
                        const unsigned int * fds, unsigned int nfds)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sock_send_fd_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_buf = copy_to_user(buf, count);
    ms->ms_count = count;
    ms->ms_fds = fds ? copy_to_user(fds, sizeof(int) * nfds) : NULL;
    ms->ms_nfds = nfds;

    retval = sgx_exitless_ocall(OCALL_SOCK_SEND_FD, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_setopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sock_setopt_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optval = copy_to_user(optval, optlen);
    ms->ms_optlen = optlen;

    retval = sgx_exitless_ocall(OCALL_SOCK_SETOPT, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sock_shutdown (int sockfd, int how)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sock_shutdown_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = sgx_exitless_ocall(OCALL_SOCK_SHUTDOWN, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_gettime_t * ms = sgx_ocalloc(sizeof(*ms));

    retval = sgx_exitless_ocall(OCALL_GETTIME, ms);
    if (!retval)
        *microsec = ms->ms_microsec;

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_sleep_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_microsec = microsec ? *microsec : 0;

    retval = sgx_ocall(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_poll (struct pollfd * fds, int nfds, uint64_t * timeout)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    ms_ocall_poll_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_fds = copy_to_user(fds, sizeof(struct pollfd) * nfds);
    ms->ms_nfds = nfds;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = sgx_exitless_ocall(OCALL_POLL, ms);
    if (retval == -EINTR && timeout)
        *timeout = ms->ms_timeout;
    if (retval >= 0)
        copy_from_user(fds, ms->ms_fds, sizeof(struct pollfd) * nfds);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;

    ms_ocall_rename_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_oldpath = copy_to_user(oldpath, oldlen);
    ms->ms_newpath = copy_to_user(newpath, newlen);

    retval = sgx_exitless_ocall(OCALL_RENAME, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int len = pathname ? strlen(pathname) + 1 : 0;

    ms_ocall_delete_t * ms = sgx_ocalloc(sizeof(*ms));
    ms->ms_pathname = copy_to_user(pathname, len);

    retval = sgx_exitless_ocall(OCALL_DELETE, ms);

    sgx_ocfree_frame(frame);
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    void* frame = sgx_ocget_frame();

    int len = strlen(command);
    const char * ms = copy_to_user(command, len + 1);
    retval = sgx_exitless_ocall(OCALL_LOAD_DEBUG, (void *) ms);

    sgx_ocfree_frame(frame);
    return retval;
}
