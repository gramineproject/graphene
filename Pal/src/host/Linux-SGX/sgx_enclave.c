#include "ecall_types.h"
#include "ocall_types.h"
#include "pal_linux_error.h"
#include "pal_security.h"
#include "rpc_queue.h"
#include "sgx_enclave.h"
#include "sgx_internal.h"

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/socket.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/signal.h>
#include <math.h>
#include <sigset.h>
#include <sys/wait.h>

#define ODEBUG(code, ms) do {} while (0)

static long sgx_ocall_exit(void* pms)
{
    ms_ocall_exit_t * ms = (ms_ocall_exit_t *) pms;
    ODEBUG(OCALL_EXIT, NULL);

    if (ms->ms_is_exitgroup && ms->ms_exitcode == PAL_WAIT_FOR_CHILDREN_EXIT) {
        /* this is a "temporary" process exiting after execve'ing a child process: it must still
         * be around until the child finally exits (because its parent in turn may wait on it) */
        SGX_DBG(DBG_I, "Temporary process exits after emulating execve, wait for child to exit\n");

        int wstatus;
        int ret = INLINE_SYSCALL(wait4, 4, /*any child*/-1, &wstatus, /*options=*/0, /*rusage=*/NULL);
        if (IS_ERR(ret)) {
            /* it's too late to recover from errors, just log it and set some reasonable exit code */
            SGX_DBG(DBG_I, "Temporary process waited for child to exit but received error %d\n", ret);
            ms->ms_exitcode = ECHILD;
        } else {
            /* Linux expects 0..127 for normal termination and 128..255 for signal termination */
            if (WIFEXITED(wstatus))
                ms->ms_exitcode = WEXITSTATUS(wstatus);
            else if (WIFSIGNALED(wstatus))
                ms->ms_exitcode = 128 + WTERMSIG(wstatus);
            else
                ms->ms_exitcode = ECHILD;
        }
    }

    if (ms->ms_exitcode != (int) ((uint8_t) ms->ms_exitcode)) {
        SGX_DBG(DBG_E, "Saturation error in exit code %d, getting rounded down to %u\n",
                ms->ms_exitcode, (uint8_t) ms->ms_exitcode);
        ms->ms_exitcode = 255;
    }

    /* exit the whole process if exit_group() */
    if (ms->ms_is_exitgroup)
        INLINE_SYSCALL(exit_group, 1, (int)ms->ms_exitcode);

    /* otherwise call SGX-related thread reset and exit this thread */
    block_async_signals(true);
    ecall_thread_reset();

    unmap_tcs();

    if (!current_enclave_thread_cnt()) {
        /* no enclave threads left, kill the whole process */
        INLINE_SYSCALL(exit_group, 1, (int)ms->ms_exitcode);
    }

    thread_exit((int)ms->ms_exitcode);
    return 0;
}

static long sgx_ocall_mmap_untrusted(void * pms)
{
    ms_ocall_mmap_untrusted_t * ms = (ms_ocall_mmap_untrusted_t *) pms;
    void * addr;

    ODEBUG(OCALL_MMAP_UNTRUSTED, ms);
    addr = (void *) INLINE_SYSCALL(mmap, 6, NULL, ms->ms_size,
                                   ms->ms_prot,
                                   (ms->ms_fd == -1) ? MAP_ANONYMOUS | MAP_PRIVATE
                                                     : MAP_FILE | MAP_SHARED,
                                   ms->ms_fd, ms->ms_offset);
    if (IS_ERR_P(addr))
        return -ERRNO_P(addr);

    ms->ms_mem = addr;
    return 0;
}

static long sgx_ocall_munmap_untrusted(void * pms)
{
    ms_ocall_munmap_untrusted_t * ms = (ms_ocall_munmap_untrusted_t *) pms;
    ODEBUG(OCALL_MUNMAP_UNTRUSTED, ms);
    INLINE_SYSCALL(munmap, 2, ALLOC_ALIGN_DOWN_PTR(ms->ms_mem),
                   ALLOC_ALIGN_UP_PTR(ms->ms_mem + ms->ms_size) -
                   ALLOC_ALIGN_DOWN_PTR(ms->ms_mem));
    return 0;
}

static long sgx_ocall_cpuid(void * pms)
{
    ms_ocall_cpuid_t * ms = (ms_ocall_cpuid_t *) pms;
    ODEBUG(OCALL_CPUID, ms);
    __asm__ volatile ("cpuid"
                  : "=a"(ms->ms_values[0]),
                    "=b"(ms->ms_values[1]),
                    "=c"(ms->ms_values[2]),
                    "=d"(ms->ms_values[3])
                  : "a"(ms->ms_leaf), "c"(ms->ms_subleaf) : "memory");
    return 0;
}

static long sgx_ocall_open(void * pms)
{
    ms_ocall_open_t * ms = (ms_ocall_open_t *) pms;
    long ret;
    ODEBUG(OCALL_OPEN, ms);
    ret = INLINE_SYSCALL(open, 3, ms->ms_pathname, ms->ms_flags|O_CLOEXEC,
                         ms->ms_mode);
    return ret;
}

static long sgx_ocall_close(void * pms)
{
    ms_ocall_close_t * ms = (ms_ocall_close_t *) pms;
    ODEBUG(OCALL_CLOSE, ms);
    INLINE_SYSCALL(close, 1, ms->ms_fd);
    return 0;
}

static long sgx_ocall_read(void * pms)
{
    ms_ocall_read_t * ms = (ms_ocall_read_t *) pms;
    long ret;
    ODEBUG(OCALL_READ, ms);
    ret = INLINE_SYSCALL(read, 3, ms->ms_fd, ms->ms_buf, ms->ms_count);
    return ret;
}

static long sgx_ocall_write(void * pms)
{
    ms_ocall_write_t * ms = (ms_ocall_write_t *) pms;
    long ret;
    ODEBUG(OCALL_WRITE, ms);
    ret = INLINE_SYSCALL(write, 3, ms->ms_fd, ms->ms_buf, ms->ms_count);
    return ret;
}

static long sgx_ocall_pread(void* pms) {
    ms_ocall_pread_t* ms = (ms_ocall_pread_t*)pms;
    long ret;
    ODEBUG(OCALL_PREAD, ms);
    ret = INLINE_SYSCALL(pread64, 4, ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);
    return ret;
}

static long sgx_ocall_pwrite(void* pms) {
    ms_ocall_pwrite_t* ms = (ms_ocall_pwrite_t*)pms;
    long ret;
    ODEBUG(OCALL_PWRITE, ms);
    ret = INLINE_SYSCALL(pwrite64, 4, ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);
    return ret;
}

static long sgx_ocall_fstat(void * pms)
{
    ms_ocall_fstat_t * ms = (ms_ocall_fstat_t *) pms;
    long ret;
    ODEBUG(OCALL_FSTAT, ms);
    ret = INLINE_SYSCALL(fstat, 2, ms->ms_fd, &ms->ms_stat);
    return ret;
}

static long sgx_ocall_fionread(void * pms)
{
    ms_ocall_fionread_t * ms = (ms_ocall_fionread_t *) pms;
    long ret;
    int val;
    ODEBUG(OCALL_FIONREAD, ms);
    ret = INLINE_SYSCALL(ioctl, 3, ms->ms_fd, FIONREAD, &val);
    return IS_ERR(ret) ? ret : val;
}

static long sgx_ocall_fsetnonblock(void * pms)
{
    ms_ocall_fsetnonblock_t * ms = (ms_ocall_fsetnonblock_t *) pms;
    long ret;
    int flags;
    ODEBUG(OCALL_FSETNONBLOCK, ms);

    ret = INLINE_SYSCALL(fcntl, 2, ms->ms_fd, F_GETFL);
    if (IS_ERR(ret))
        return ret;

    flags = ret;
    if (ms->ms_nonblocking) {
        if (!(flags & O_NONBLOCK))
            ret = INLINE_SYSCALL(fcntl, 3, ms->ms_fd, F_SETFL,
                                 flags | O_NONBLOCK);
    } else {
        if (flags & O_NONBLOCK)
            ret = INLINE_SYSCALL(fcntl, 3, ms->ms_fd, F_SETFL,
                                 flags & ~O_NONBLOCK);
    }

    return ret;
}

static long sgx_ocall_fchmod(void * pms)
{
    ms_ocall_fchmod_t * ms = (ms_ocall_fchmod_t *) pms;
    long ret;
    ODEBUG(OCALL_FCHMOD, ms);
    ret = INLINE_SYSCALL(fchmod, 2, ms->ms_fd, ms->ms_mode);
    return ret;
}

static long sgx_ocall_fsync(void * pms)
{
    ms_ocall_fsync_t * ms = (ms_ocall_fsync_t *) pms;
    ODEBUG(OCALL_FSYNC, ms);
    INLINE_SYSCALL(fsync, 1, ms->ms_fd);
    return 0;
}

static long sgx_ocall_ftruncate(void * pms)
{
    ms_ocall_ftruncate_t * ms = (ms_ocall_ftruncate_t *) pms;
    long ret;
    ODEBUG(OCALL_FTRUNCATE, ms);
    ret = INLINE_SYSCALL(ftruncate, 2, ms->ms_fd, ms->ms_length);
    return ret;
}

static long sgx_ocall_mkdir(void * pms)
{
    ms_ocall_mkdir_t * ms = (ms_ocall_mkdir_t *) pms;
    long ret;
    ODEBUG(OCALL_MKDIR, ms);
    ret = INLINE_SYSCALL(mkdir, 2, ms->ms_pathname, ms->ms_mode);
    return ret;
}

static long sgx_ocall_getdents(void * pms)
{
    ms_ocall_getdents_t * ms = (ms_ocall_getdents_t *) pms;
    long ret;
    ODEBUG(OCALL_GETDENTS, ms);
    ret = INLINE_SYSCALL(getdents64, 3, ms->ms_fd, ms->ms_dirp, ms->ms_size);
    return ret;
}

static long sgx_ocall_resume_thread(void * pms)
{
    ODEBUG(OCALL_RESUME_THREAD, pms);
    return interrupt_thread(pms);
}

static long sgx_ocall_clone_thread(void * pms)
{
    __UNUSED(pms);
    ODEBUG(OCALL_CLONE_THREAD, pms);
    return clone_thread();
}

static long sgx_ocall_create_process(void * pms)
{
    ms_ocall_create_process_t * ms = (ms_ocall_create_process_t *) pms;
    ODEBUG(OCALL_CREATE_PROCESS, ms);
    long ret = sgx_create_process(ms->ms_uri, ms->ms_nargs, ms->ms_args, &ms->ms_stream_fd);
    if (ret < 0)
        return ret;
    ms->ms_pid = ret;
    return 0;
}

static long sgx_ocall_futex(void * pms)
{
    ms_ocall_futex_t * ms = (ms_ocall_futex_t *) pms;
    long ret;
    ODEBUG(OCALL_FUTEX, ms);
    struct timespec* ts = NULL;
    if (ms->ms_timeout_us >= 0) {
        ts = __alloca(sizeof(struct timespec));
        ts->tv_sec = ms->ms_timeout_us / 1000000;
        ts->tv_nsec = (ms->ms_timeout_us - ts->tv_sec * 1000000) * 1000;
    }
    ret = INLINE_SYSCALL(futex, 6, ms->ms_futex, ms->ms_op, ms->ms_val,
                         ts, NULL, 0);
    return ret;
}

static long sgx_ocall_socketpair(void * pms)
{
    ms_ocall_socketpair_t * ms = (ms_ocall_socketpair_t *) pms;
    long ret;
    ODEBUG(OCALL_SOCKETPAIR, ms);
    ret = INLINE_SYSCALL(socketpair, 4, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol, &ms->ms_sockfds);
    return ret;
}

static long sock_getopt(int fd, struct sockopt * opt)
{
    SGX_DBG(DBG_M, "sock_getopt (fd = %d, sockopt addr = %p) is not implemented \
            always returns 0\n", fd, opt);
    /* initialize *opt with constant */
    *opt = (struct sockopt){0};
    opt->reuseaddr = 1;
    return 0;
}

static long sgx_ocall_listen(void * pms)
{
    ms_ocall_listen_t * ms = (ms_ocall_listen_t *) pms;
    long ret;
    int fd;
    ODEBUG(OCALL_LISTEN, ms);

    ret = INLINE_SYSCALL(socket, 3, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol);
    if (IS_ERR(ret))
        goto err;

    fd = ret;

    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (IS_ERR(ret))
        goto err_fd;

    if (ms->ms_domain == AF_INET6) {
        /* IPV6_V6ONLY socket option can only be set before first bind */
        ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ms->ms_ipv6_v6only,
                             sizeof(ms->ms_ipv6_v6only));
        if (IS_ERR(ret))
            goto err_fd;
    }

    ret = INLINE_SYSCALL(bind, 3, fd, ms->ms_addr, ms->ms_addrlen);
    if (IS_ERR(ret))
        goto err_fd;

    if (ms->ms_addr) {
        socklen_t addrlen = ms->ms_addrlen;
        ret = INLINE_SYSCALL(getsockname, 3, fd, ms->ms_addr, &addrlen);
        if (IS_ERR(ret))
            goto err_fd;
        ms->ms_addrlen = addrlen;
    }

    if (ms->ms_type & SOCK_STREAM) {
        ret = INLINE_SYSCALL(listen, 2, fd, DEFAULT_BACKLOG);
        if (IS_ERR(ret))
            goto err_fd;
    }

    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (IS_ERR(ret))
        goto err_fd;

    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static long sgx_ocall_accept(void * pms)
{
    ms_ocall_accept_t * ms = (ms_ocall_accept_t *) pms;
    long ret;
    int fd;
    ODEBUG(OCALL_ACCEPT, ms);
    socklen_t addrlen = ms->ms_addrlen;

    ret = INLINE_SYSCALL(accept4, 4, ms->ms_sockfd, ms->ms_addr,
                         &addrlen, O_CLOEXEC);
    if (IS_ERR(ret))
        goto err;

    fd = ret;
    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (IS_ERR(ret))
        goto err_fd;

    ms->ms_addrlen = addrlen;
    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static long sgx_ocall_connect(void * pms)
{
    ms_ocall_connect_t * ms = (ms_ocall_connect_t *) pms;
    long ret;
    int fd;
    ODEBUG(OCALL_CONNECT, ms);

    ret = INLINE_SYSCALL(socket, 3, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol);
    if (IS_ERR(ret))
        goto err;

    fd = ret;

    if (ms->ms_bind_addr && ms->ms_bind_addr->sa_family) {
        if (ms->ms_domain == AF_INET6) {
            /* IPV6_V6ONLY socket option can only be set before first bind */
            ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ms->ms_ipv6_v6only,
                                 sizeof(ms->ms_ipv6_v6only));
            if (IS_ERR(ret))
                goto err_fd;
        }

        ret = INLINE_SYSCALL(bind, 3, fd, ms->ms_bind_addr,
                             ms->ms_bind_addrlen);
        if (IS_ERR(ret))
            goto err_fd;
    }

    if (ms->ms_addr) {
        ret = INLINE_SYSCALL(connect, 3, fd, ms->ms_addr, ms->ms_addrlen);

        if (IS_ERR(ret) && ERRNO(ret) == EINPROGRESS) {
            do {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0, };
                ret = INLINE_SYSCALL(ppoll, 4, &pfd, 1, NULL, NULL);
            } while (IS_ERR(ret) &&
                    ERRNO(ret) == -EWOULDBLOCK);
        }

        if (IS_ERR(ret))
            goto err_fd;
    }

    if (ms->ms_bind_addr && !ms->ms_bind_addr->sa_family) {
        socklen_t addrlen = ms->ms_bind_addrlen;
        ret = INLINE_SYSCALL(getsockname, 3, fd, ms->ms_bind_addr,
                             &addrlen);
        if (IS_ERR(ret))
            goto err_fd;
        ms->ms_bind_addrlen = addrlen;
    }

    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (IS_ERR(ret))
        goto err_fd;

    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static long sgx_ocall_recv(void * pms)
{
    ms_ocall_recv_t * ms = (ms_ocall_recv_t *) pms;
    long ret;
    ODEBUG(OCALL_RECV, ms);
    struct sockaddr * addr = ms->ms_addr;
    socklen_t addrlen = ms->ms_addr ? ms->ms_addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = ms->ms_buf;
    iov[0].iov_len     = ms->ms_count;
    hdr.msg_name       = addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ms->ms_control;
    hdr.msg_controllen = ms->ms_controllen;
    hdr.msg_flags      = 0;

    ret = INLINE_SYSCALL(recvmsg, 3, ms->ms_sockfd, &hdr, 0);

    if (!IS_ERR(ret) && hdr.msg_name) {
        /* note that ms->ms_addr is filled by recvmsg() itself */
        ms->ms_addrlen = hdr.msg_namelen;
    }

    if (!IS_ERR(ret) && hdr.msg_control) {
        /* note that ms->ms_control is filled by recvmsg() itself */
        ms->ms_controllen = hdr.msg_controllen;
    }

    return ret;
}

static long sgx_ocall_send(void * pms)
{
    ms_ocall_send_t * ms = (ms_ocall_send_t *) pms;
    long ret;
    ODEBUG(OCALL_SEND, ms);
    const struct sockaddr * addr = ms->ms_addr;
    socklen_t addrlen = ms->ms_addr ? ms->ms_addrlen : 0;

    struct msghdr hdr;
    struct iovec iov[1];

    iov[0].iov_base    = (void*)ms->ms_buf;
    iov[0].iov_len     = ms->ms_count;
    hdr.msg_name       = (void*)addr;
    hdr.msg_namelen    = addrlen;
    hdr.msg_iov        = iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = ms->ms_control;
    hdr.msg_controllen = ms->ms_controllen;
    hdr.msg_flags      = 0;

    ret = INLINE_SYSCALL(sendmsg, 3, ms->ms_sockfd, &hdr, MSG_NOSIGNAL);
    return ret;
}

static long sgx_ocall_setsockopt(void * pms)
{
    ms_ocall_setsockopt_t * ms = (ms_ocall_setsockopt_t *) pms;
    long ret;
    ODEBUG(OCALL_SETSOCKOPT, ms);
    ret = INLINE_SYSCALL(setsockopt, 5,
                         ms->ms_sockfd, ms->ms_level, ms->ms_optname,
                         ms->ms_optval, ms->ms_optlen);
    return ret;
}

static long sgx_ocall_shutdown(void * pms)
{
    ms_ocall_shutdown_t * ms = (ms_ocall_shutdown_t *) pms;
    ODEBUG(OCALL_SHUTDOWN, ms);
    INLINE_SYSCALL(shutdown, 2, ms->ms_sockfd, ms->ms_how);
    return 0;
}

static long sgx_ocall_gettime(void * pms)
{
    ms_ocall_gettime_t * ms = (ms_ocall_gettime_t *) pms;
    ODEBUG(OCALL_GETTIME, ms);
    struct timeval tv;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    ms->ms_microsec = tv.tv_sec * 1000000UL + tv.tv_usec;
    return 0;
}

static long sgx_ocall_sleep(void * pms)
{
    ms_ocall_sleep_t * ms = (ms_ocall_sleep_t *) pms;
    long ret;
    ODEBUG(OCALL_SLEEP, ms);
    if (!ms->ms_microsec) {
        INLINE_SYSCALL(sched_yield, 0);
        return 0;
    }
    struct timespec req, rem;
    unsigned long microsec = ms->ms_microsec;
    const unsigned long VERY_LONG_TIME_IN_US = 1000000L * 60 * 60 * 24 * 365 * 128;
    if (ms->ms_microsec > VERY_LONG_TIME_IN_US) {
        /* avoid overflow with time_t */
        req.tv_sec  = VERY_LONG_TIME_IN_US / 1000000;
        req.tv_nsec = 0;
    } else {
        req.tv_sec = ms->ms_microsec / 1000000;
        req.tv_nsec = (microsec - req.tv_sec * 1000000) * 1000;
    }

    ret = INLINE_SYSCALL(nanosleep, 2, &req, &rem);
    if (IS_ERR(ret) && ERRNO(ret) == EINTR)
        ms->ms_microsec = rem.tv_sec * 1000000UL + rem.tv_nsec / 1000UL;
    return ret;
}

static long sgx_ocall_poll(void * pms)
{
    ms_ocall_poll_t * ms = (ms_ocall_poll_t *) pms;
    long ret;
    ODEBUG(OCALL_POLL, ms);
    struct timespec * ts = NULL;
    if (ms->ms_timeout_us >= 0) {
        ts = __alloca(sizeof(struct timespec));
        ts->tv_sec = ms->ms_timeout_us / 1000000;
        ts->tv_nsec = (ms->ms_timeout_us - ts->tv_sec * 1000000) * 1000;
    }
    ret = INLINE_SYSCALL(ppoll, 4, ms->ms_fds, ms->ms_nfds, ts, NULL);
    return ret;
}

static long sgx_ocall_rename(void * pms)
{
    ms_ocall_rename_t * ms = (ms_ocall_rename_t *) pms;
    long ret;
    ODEBUG(OCALL_RENAME, ms);
    ret = INLINE_SYSCALL(rename, 2, ms->ms_oldpath, ms->ms_newpath);
    return ret;
}

static long sgx_ocall_delete(void * pms)
{
    ms_ocall_delete_t * ms = (ms_ocall_delete_t *) pms;
    long ret;
    ODEBUG(OCALL_DELETE, ms);

    ret = INLINE_SYSCALL(unlink, 1, ms->ms_pathname);

    if (IS_ERR(ret) && ERRNO(ret) == EISDIR)
        ret = INLINE_SYSCALL(rmdir, 1, ms->ms_pathname);

    return ret;
}

static long sgx_ocall_eventfd (void * pms)
{
    ms_ocall_eventfd_t * ms = (ms_ocall_eventfd_t *) pms;
    long ret;
    ODEBUG(OCALL_EVENTFD, ms);

    ret = INLINE_SYSCALL(eventfd2, 2, ms->ms_initval, ms->ms_flags);

    return ret;
}

void load_gdb_command (const char * command);

static long sgx_ocall_load_debug(void * pms)
{
    const char * command = (const char *) pms;
    ODEBUG(OCALL_LOAD_DEBUG, (void *) command);
    load_gdb_command(command);
    return 0;
}

static long sgx_ocall_get_quote(void* pms) {
    ms_ocall_get_quote_t* ms = (ms_ocall_get_quote_t*)pms;
    ODEBUG(OCALL_GET_QUOTE, ms);
    return retrieve_quote(&ms->ms_spid, ms->ms_linkable, &ms->ms_report, &ms->ms_nonce,
                          &ms->ms_quote, &ms->ms_quote_len);
}

sgx_ocall_fn_t ocall_table[OCALL_NR] = {
        [OCALL_EXIT]             = sgx_ocall_exit,
        [OCALL_MMAP_UNTRUSTED]   = sgx_ocall_mmap_untrusted,
        [OCALL_MUNMAP_UNTRUSTED] = sgx_ocall_munmap_untrusted,
        [OCALL_CPUID]            = sgx_ocall_cpuid,
        [OCALL_OPEN]             = sgx_ocall_open,
        [OCALL_CLOSE]            = sgx_ocall_close,
        [OCALL_READ]             = sgx_ocall_read,
        [OCALL_WRITE]            = sgx_ocall_write,
        [OCALL_PREAD]            = sgx_ocall_pread,
        [OCALL_PWRITE]           = sgx_ocall_pwrite,
        [OCALL_FSTAT]            = sgx_ocall_fstat,
        [OCALL_FIONREAD]         = sgx_ocall_fionread,
        [OCALL_FSETNONBLOCK]     = sgx_ocall_fsetnonblock,
        [OCALL_FCHMOD]           = sgx_ocall_fchmod,
        [OCALL_FSYNC]            = sgx_ocall_fsync,
        [OCALL_FTRUNCATE]        = sgx_ocall_ftruncate,
        [OCALL_MKDIR]            = sgx_ocall_mkdir,
        [OCALL_GETDENTS]         = sgx_ocall_getdents,
        [OCALL_RESUME_THREAD]    = sgx_ocall_resume_thread,
        [OCALL_CLONE_THREAD]     = sgx_ocall_clone_thread,
        [OCALL_CREATE_PROCESS]   = sgx_ocall_create_process,
        [OCALL_FUTEX]            = sgx_ocall_futex,
        [OCALL_SOCKETPAIR]       = sgx_ocall_socketpair,
        [OCALL_LISTEN]           = sgx_ocall_listen,
        [OCALL_ACCEPT]           = sgx_ocall_accept,
        [OCALL_CONNECT]          = sgx_ocall_connect,
        [OCALL_RECV]             = sgx_ocall_recv,
        [OCALL_SEND]             = sgx_ocall_send,
        [OCALL_SETSOCKOPT]       = sgx_ocall_setsockopt,
        [OCALL_SHUTDOWN]         = sgx_ocall_shutdown,
        [OCALL_GETTIME]          = sgx_ocall_gettime,
        [OCALL_SLEEP]            = sgx_ocall_sleep,
        [OCALL_POLL]             = sgx_ocall_poll,
        [OCALL_RENAME]           = sgx_ocall_rename,
        [OCALL_DELETE]           = sgx_ocall_delete,
        [OCALL_LOAD_DEBUG]       = sgx_ocall_load_debug,
        [OCALL_EVENTFD]          = sgx_ocall_eventfd,
        [OCALL_GET_QUOTE]        = sgx_ocall_get_quote,
    };

#define EDEBUG(code, ms) do {} while (0)

rpc_queue_t* g_rpc_queue = NULL; /* pointer to untrusted queue */

static int rpc_thread_loop(void* arg) {
    __UNUSED(arg);
    long mytid = INLINE_SYSCALL(gettid, 0);

    /* block all signals except SIGUSR2 for RPC thread */
    __sigset_t mask;
    __sigfillset(&mask);
    __sigdelset(&mask, SIGUSR2);
    INLINE_SYSCALL(rt_sigprocmask, 4, SIG_SETMASK, &mask, NULL, sizeof(mask));

    spinlock_lock(&g_rpc_queue->lock);
    g_rpc_queue->rpc_threads[g_rpc_queue->rpc_threads_cnt] = mytid;
    g_rpc_queue->rpc_threads_cnt++;
    spinlock_unlock(&g_rpc_queue->lock);

    while (1) {
        rpc_request_t* req = rpc_dequeue(g_rpc_queue);
        if (!req) {
            __asm__ volatile("pause");
            continue;
        }

        /* call actual function and notify awaiting enclave thread when done */
        sgx_ocall_fn_t f = ocall_table[req->ocall_index];
        req->result = f(req->buffer);

        /* this code is based on Mutex 2 from Futexes are Tricky */
        int old_lock_state = __atomic_fetch_sub(&req->lock.lock, 1, __ATOMIC_ACQ_REL);
        if (old_lock_state == SPINLOCK_LOCKED_WITH_WAITERS) {
            /* must unlock and wake waiters */
            spinlock_unlock(&req->lock);
            int ret = INLINE_SYSCALL(futex, 6, &req->lock.lock, FUTEX_WAKE_PRIVATE,
                                     1, NULL, NULL, 0);
            if (ret == -1)
                SGX_DBG(DBG_E, "RPC thread failed to wake up enclave thread\n");
        }
    }

    /* NOTREACHED */
    return 0;
}

static int start_rpc(size_t num_of_threads) {
    g_rpc_queue = (rpc_queue_t*)INLINE_SYSCALL(mmap, 6, NULL,
                                               ALIGN_UP(sizeof(rpc_queue_t), PRESET_PAGESIZE),
                                               PROT_READ | PROT_WRITE,
                                               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (IS_ERR_P(g_rpc_queue))
        return -ENOMEM;

    /* initialize g_rpc_queue just for sanity, it will be overwritten by in-enclave code */
    rpc_queue_init(g_rpc_queue);

    for (size_t i = 0; i < num_of_threads; i++) {
        void* stack = (void*)INLINE_SYSCALL(mmap, 6, NULL, RPC_STACK_SIZE,
                                            PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_ERR_P(stack))
            return -ENOMEM;

        void* child_stack_top = stack + RPC_STACK_SIZE;
        child_stack_top = ALIGN_DOWN_PTR(child_stack_top, 16);

        int dummy_parent_tid_field = 0;
        int ret = clone(rpc_thread_loop, child_stack_top,
                        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM |
                        CLONE_THREAD | CLONE_SIGHAND | CLONE_PTRACE | CLONE_PARENT_SETTID,
                        NULL, &dummy_parent_tid_field, NULL);

        if (IS_ERR(ret)) {
            INLINE_SYSCALL(munmap, 2, stack, RPC_STACK_SIZE);
            return -ENOMEM;
        }
    }

    /* wait until all RPC threads are initialized in rpc_thread_loop */
    while (1) {
        spinlock_lock(&g_rpc_queue->lock);
        size_t n = g_rpc_queue->rpc_threads_cnt;
        spinlock_unlock(&g_rpc_queue->lock);
        if (n == pal_enclave.rpc_thread_num)
            break;
        INLINE_SYSCALL(sched_yield, 0);
    }

    return 0;
}


int ecall_enclave_start (char * args, size_t args_size, char * env, size_t env_size)
{
    g_rpc_queue = NULL;

    if (pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }

    ms_ecall_enclave_start_t ms;
    ms.ms_args = args;
    ms.ms_args_size = args_size;
    ms.ms_env = env;
    ms.ms_env_size = env_size;
    ms.ms_sec_info = &pal_enclave.pal_sec;
    ms.rpc_queue = g_rpc_queue;
    EDEBUG(ECALL_ENCLAVE_START, &ms);
    return sgx_ecall(ECALL_ENCLAVE_START, &ms);
}

int ecall_thread_start (void)
{
    EDEBUG(ECALL_THREAD_START, NULL);
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    EDEBUG(ECALL_THREAD_RESET, NULL);
    return sgx_ecall(ECALL_THREAD_RESET, NULL);
}

noreturn void __abort(void) {
    INLINE_SYSCALL(exit_group, 1, -1);
    while (true) {
        /* nothing */;
    }
}
