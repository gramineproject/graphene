/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#ifndef _SHIM_TABLE_H_
#define _SHIM_TABLE_H_

#include <stdnoreturn.h>
#if defined(__i386__) || defined(__x86_64__)
#include <asm/ldt.h>
#endif

#include "shim_types.h"

void debug_unsupp(int num);

typedef void (*shim_fp)(void);

extern shim_fp shim_table[];

/* syscall entries */
long __shim_read(long, long, long);
long __shim_write(long, long, long);
long __shim_open(long, long, long);
long __shim_close(long);
long __shim_stat(long, long);
long __shim_fstat(long, long);
long __shim_lstat(long, long);
long __shim_poll(long, long, long);
long __shim_lseek(long, long, long);
long __shim_mmap(long, long, long, long, long, long);
long __shim_mprotect(long, long, long);
long __shim_munmap(long, long);
long __shim_brk(long);
long __shim_rt_sigaction(long, long, long, long);
long __shim_rt_sigprocmask(long, long, long);
long __shim_rt_sigreturn(long);
long __shim_ioctl(long, long, long);
long __shim_pread64(long, long, long, long);
long __shim_pwrite64(long, long, long, long);
long __shim_readv(long, long, long);
long __shim_writev(long, long, long);
long __shim_access(long, long);
long __shim_pipe(long);
long __shim_select(long, long, long, long, long);
long __shim_sched_yield(void);
long __shim_mremap(long, long, long, long, long);
long __shim_msync(long, long, long);
long __shim_mincore(long, long, long);
long __shim_madvise(long, long, long);
long __shim_shmget(long, long, long);
long __shim_shmat(long, long, long);
long __shim_shmctl(long, long, long);
long __shim_dup(long);
long __shim_dup2(long, long);
long __shim_pause(void);
long __shim_nanosleep(long, long);
long __shim_getitimer(long, long);
long __shim_alarm(long);
long __shim_setitimer(long, long, long);
long __shim_getpid(void);
long __shim_sendfile(long, long, long, long);
long __shim_socket(long, long, long);
long __shim_connect(long, long, long);
long __shim_accept(long, long, long);
long __shim_sendto(long, long, long, long, long, long);
long __shim_recvfrom(long, long, long, long, long, long);
long __shim_sendmsg(long, long, long);
long __shim_recvmsg(long, long, long);
long __shim_shutdown(long, long);
long __shim_bind(long, long, long);
long __shim_listen(long, long);
long __shim_getsockname(long, long, long);
long __shim_getpeername(long, long, long);
long __shim_socketpair(long, long, long, long);
long __shim_setsockopt(long, long, long, long, long);
long __shim_getsockopt(long, long, long, long, long);
long __shim_clone(long, long, long, long, long);
long __shim_fork(void);
long __shim_vfork(void);
long __shim_execve(long, long, long);
long __shim_exit(long);
long __shim_wait4(long, long, long, long);
long __shim_kill(long, long);
long __shim_uname(long);
long __shim_semget(long, long, long);
long __shim_semop(long, long, long);
long __shim_semctl(long, long, long, long);
long __shim_shmdt(long);
long __shim_msgget(long, long);
long __shim_msgsnd(long, long, long, long);
long __shim_msgrcv(long, long, long, long, long);
long __shim_msgctl(long, long, long);
long __shim_fcntl(long, long, long);
long __shim_flock(long, long);
long __shim_fsync(long);
long __shim_fdatasync(long);
long __shim_truncate(long, long);
long __shim_ftruncate(long, long);
long __shim_getdents(long, long, long);
long __shim_getcwd(long, long);
long __shim_chdir(long);
long __shim_fchdir(long);
long __shim_rename(long, long);
long __shim_mkdir(long, long);
long __shim_rmdir(long);
long __shim_creat(long, long);
long __shim_link(long, long);
long __shim_unlink(long);
long __shim_symlink(long, long);
long __shim_readlink(long, long, long);
long __shim_chmod(long, long);
long __shim_fchmod(long, long);
long __shim_chown(long, long, long);
long __shim_fchown(long, long, long);
long __shim_lchown(long, long, long);
long __shim_umask(long);
long __shim_gettimeofday(long, long);
long __shim_getrlimit(long, long);
long __shim_getrusage(long, long);
long __shim_sysinfo(long);
long __shim_times(long);
long __shim_ptrace(long, long, long, long);
long __shim_getuid(void);
long __shim_syslog(long, long, long);
long __shim_getgid(void);
long __shim_setuid(long);
long __shim_setgid(long);
long __shim_geteuid(void);
long __shim_getegid(void);
long __shim_setpgid(long, long);
long __shim_getppid(void);
long __shim_getpgrp(void);
long __shim_setsid(void);
long __shim_setreuid(long, long);
long __shim_setregid(long, long);
long __shim_getgroups(long, long);
long __shim_setgroups(long, long);
long __shim_setresuid(long, long, long);
long __shim_getresuid(long, long, long);
long __shim_setresgid(long, long, long);
long __shim_getresgid(long, long, long);
long __shim_getpgid(long);
long __shim_setfsuid(long);
long __shim_setfsgid(long);
long __shim_getsid(long);
long __shim_capget(long, long);
long __shim_capset(long, long);
long __shim_rt_sigpending(long, long);
long __shim_rt_sigtimedwait(long, long, long, long);
long __shim_rt_sigqueueinfo(long, long, long);
long __shim_rt_sigsuspend(long);
long __shim_sigaltstack(long, long);
long __shim_utime(long, long);
long __shim_mknod(long, long, long);
long __shim_uselib(long);
long __shim_personality(long);
long __shim_ustat(long, long);
long __shim_statfs(long, long);
long __shim_fstatfs(long, long);
long __shim_sysfs(long, long, long);
long __shim_getpriority(long, long);
long __shim_setpriority(long, long, long);
long __shim_sched_setparam(long, long);
long __shim_sched_getparam(long, long);
long __shim_sched_setscheduler(long, long, long);
long __shim_sched_getscheduler(long);
long __shim_sched_get_priority_max(long);
long __shim_sched_get_priority_min(long);
long __shim_sched_rr_get_interval(long, long);
long __shim_mlock(long, long);
long __shim_munlock(long, long);
long __shim_mlockall(long);
long __shim_munlockall(void);
long __shim_vhangup(void);
long __shim_modify_ldt(long, long, long);
long __shim_pivot_root(long, long);
long __shim__sysctl(long);
long __shim_prctl(long, long, long, long, long);
long __shim_arch_prctl(long, long);
long __shim_adjtimex(long);
long __shim_setrlimit(long, long);
long __shim_chroot(long);
long __shim_sync(void);
long __shim_acct(long);
long __shim_settimeofday(long, long);
long __shim_mount(long, long, long, long, long);
long __shim_umount2(long, long);
long __shim_swapon(long, long);
long __shim_swapoff(long);
long __shim_reboot(long, long, long, long);
long __shim_sethostname(long, long);
long __shim_setdomainname(long, long);
long __shim_iopl(long);
long __shim_ioperm(long, long, long);
long __shim_create_module(long, long);
long __shim_init_module(long, long, long);
long __shim_delete_module(long, long);
long __shim_get_kernel_syms(long);
long __shim_query_module(long, long, long, long, long);
long __shim_quotactl(long, long, long, long);
long __shim_nfsservctl(long, long, long);
long __shim_gettid(void);
long __shim_readahead(long, long, long);
long __shim_setxattr(long, long, long, long, long);
long __shim_lsetxattr(long, long, long, long, long);
long __shim_fsetxattr(long, long, long, long, long);
long __shim_getxattr(long, long, long, long);
long __shim_lgetxattr(long, long, long, long);
long __shim_fgetxattr(long, long, long, long);
long __shim_listxattr(long, long, long);
long __shim_llistxattr(long, long, long);
long __shim_flistxattr(long, long, long);
long __shim_removexattr(long, long);
long __shim_lremovexattr(long, long);
long __shim_fremovexattr(long, long);
long __shim_tkill(long, long);
long __shim_time(long);
long __shim_futex(long, long, long, long, long, long);
long __shim_sched_setaffinity(long, long, long);
long __shim_sched_getaffinity(long, long, long);
long __shim_set_thread_area(long);
long __shim_io_setup(long, long);
long __shim_io_destroy(long);
long __shim_io_getevents(long, long, long, long, long);
long __shim_io_submit(long, long, long);
long __shim_io_cancel(long, long, long);
long __shim_get_thread_area(long);
long __shim_lookup_dcookie(long, long, long);
long __shim_epoll_create(long);
long __shim_remap_file_pages(long, long, long, long, long);
long __shim_getdents64(long, long, long);
long __shim_set_tid_address(long);
long __shim_restart_syscall(void);
long __shim_semtimedop(long, long, long, long);
long __shim_fadvise64(long, long, long, long);
long __shim_timer_create(long, long, long);
long __shim_timer_settime(long, long, long, long);
long __shim_timer_gettime(long, long);
long __shim_timer_getoverrun(long);
long __shim_timer_delete(long);
long __shim_clock_settime(long, long);
long __shim_clock_gettime(long, long);
long __shim_clock_getres(long, long);
long __shim_clock_nanosleep(long, long, long, long);
long __shim_exit_group(long);
long __shim_epoll_wait(long, long, long, long);
long __shim_epoll_ctl(long, long, long, long);
long __shim_tgkill(long, long, long);
long __shim_utimes(long, long);
long __shim_mbind(long, long, long, long, long, long);
long __shim_set_mempolicy(long, long, long);
long __shim_get_mempolicy(long, long, long, long, long);
long __shim_mq_open(long, long, long, long);
long __shim_mq_unlink(long);
long __shim_mq_timedsend(long, long, long, long, long);
long __shim_mq_timedreceive(long, long, long, long, long);
long __shim_mq_notify(long, long);
long __shim_mq_getsetattr(long, long, long);
long __shim_kexec_load(long, long, long, long);
long __shim_waitid(long, long, long, long, long);
long __shim_add_key(long, long, long, long, long);
long __shim_request_key(long, long, long, long);
long __shim_keyctl(long, long, long, long, long);
long __shim_ioprio_set(long, long, long);
long __shim_ioprio_get(long, long);
long __shim_inotify_init(void);
long __shim_inotify_add_watch(long, long, long);
long __shim_inotify_rm_watch(long, long);
long __shim_migrate_pages(long, long, long, long);
long __shim_openat(long, long, long, long);
long __shim_mkdirat(long, long, long);
long __shim_mknodat(long, long, long, long);
long __shim_fchownat(long, long, long, long, long);
long __shim_futimesat(long, long, long);
long __shim_newfstatat(long, long, long, long);
long __shim_unlinkat(long, long, long);
long __shim_renameat(long, long, long, long);
long __shim_linkat(long, long, long, long, long);
long __shim_symlinkat(long, long, long);
long __shim_readlinkat(long, long, long, long);
long __shim_fchmodat(long, long, long);
long __shim_faccessat(long, long, long);
long __shim_pselect6(long, long, long, long, long, long);
long __shim_ppoll(long, long, long, long, long);
long __shim_unshare(long);
long __shim_set_robust_list(long, long);
long __shim_get_robust_list(long, long, long);
long __shim_splice(long, long, long, long, long, long);
long __shim_tee(long, long, long, long);
long __shim_sync_file_range(long, long, long, long);
long __shim_vmsplice(long, long, long, long);
long __shim_move_pages(long, long, long, long, long, long);
long __shim_utimensat(long, long, long, long);
long __shim_epoll_pwait(long, long, long, long, long, long);
long __shim_signalfd(long, long, long);
long __shim_timerfd_create(long, long);
long __shim_eventfd(long);
long __shim_fallocate(long, long, long, long);
long __shim_timerfd_settime(long, long, long, long);
long __shim_timerfd_gettime(long, long);
long __shim_accept4(long, long, long, long);
long __shim_signalfd4(long, long, long, long);
long __shim_eventfd2(long, long);
long __shim_epoll_create1(long);
long __shim_dup3(long, long, long);
long __shim_pipe2(long, long);
long __shim_inotify_init1(long);
long __shim_preadv(long, long, long, long, long);
long __shim_pwritev(long, long, long, long, long);
long __shim_rt_tgsigqueueinfo(long, long, long, long);
long __shim_perf_event_open(long, long, long, long, long);
long __shim_recvmmsg(long, long, long, long, long);
long __shim_fanotify_init(long, long);
long __shim_fanotify_mark(long, long, long, long, long);
long __shim_prlimit64(long, long, long, long);
long __shim_name_to_handle_at(long, long, long, long, long);
long __shim_open_by_handle_at(long, long, long);
long __shim_clock_adjtime(long, long);
long __shim_syncfs(long);
long __shim_sendmmsg(long, long, long, long);
long __shim_setns(long, long);
long __shim_getcpu(long, long, long);
long __shim_process_vm_readv(long, long, long, long, long, long);
long __shim_process_vm_writev(long, long, long, long, long, long);
long __shim_kcmp(long, long, long, long, long);
long __shim_finit_module(long, long, long);
long __shim_sched_setattr(long, long, long);
long __shim_sched_getattr(long, long, long, long);
long __shim_renameat2(long, long, long, long, long);
long __shim_seccomp(long, long, long);
long __shim_getrandom(long, long, long);
long __shim_memfd_create(long, long);
long __shim_kexec_file_load(long, long, long, long, long);
long __shim_bpf(long, long, long);
long __shim_execveat(long, long, long, long, long);
long __shim_userfaultfd(long);
long __shim_membarrier(long, long);
long __shim_mlock2(long, long, long);
long __shim_copy_file_range(long, long, long, long, long, long);
long __shim_preadv2(long, long, long, long, long, long);
long __shim_pwritev2(long, long, long, long, long, long);
long __shim_pkey_mprotect(long, long, long, long);
long __shim_pkey_alloc(long, long);
long __shim_pkey_free(long);
long __shim_statx(long, long, long, long, long);
long __shim_io_pgetevents(long, long, long, long, long, long);
long __shim_rseq(long, long, long, long);
long __shim_pidfd_send_signal(long, long, long, long);
long __shim_io_uring_setup(long, long);
long __shim_io_uring_enter(long, long, long, long, long, long);
long __shim_io_uring_register(long, long, long, long);

/* syscall implementation */
size_t shim_do_read(int fd, void* buf, size_t count);
size_t shim_do_write(int fd, const void* buf, size_t count);
int shim_do_open(const char* file, int flags, mode_t mode);
int shim_do_close(int fd);
int shim_do_stat(const char* file, struct stat* statbuf);
int shim_do_fstat(int fd, struct stat* statbuf);
int shim_do_lstat(const char* file, struct stat* stat);
int shim_do_statfs(const char* path, struct statfs* buf);
int shim_do_fstatfs(int fd, struct statfs* buf);
int shim_do_poll(struct pollfd* fds, nfds_t nfds, int timeout);
off_t shim_do_lseek(int fd, off_t offset, int origin);
void* shim_do_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int shim_do_mprotect(void* addr, size_t len, int prot);
int shim_do_munmap(void* addr, size_t len);
void* shim_do_brk(void* brk);
int shim_do_sigaction(int signum, const struct __kernel_sigaction* act,
                      struct __kernel_sigaction* oldact, size_t sigsetsize);
int shim_do_sigprocmask(int how, const __sigset_t* set, __sigset_t* oldset);
int shim_do_sigreturn(int __unused);
long shim_do_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
ssize_t shim_do_pread64(int fd, char* buf, size_t count, loff_t pos);
ssize_t shim_do_pwrite64(int fd, char* buf, size_t count, loff_t pos);
ssize_t shim_do_readv(int fd, const struct iovec* vec, int vlen);
ssize_t shim_do_writev(int fd, const struct iovec* vec, int vlen);
int shim_do_access(const char* file, mode_t mode);
int shim_do_pipe(int* fildes);
int shim_do_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* errorfds,
                   struct __kernel_timeval* timeout);
int shim_do_sched_yield(void);
void* shim_do_mremap(void* addr, size_t old_len, size_t new_len, int flags, void* new_addr);
int shim_do_msync(void* start, size_t len, int flags);
int shim_do_mincore(void* start, size_t len, unsigned char* vec);
long shim_do_madvise(unsigned long start, size_t len_in, int behavior);
int shim_do_dup(unsigned int fd);
int shim_do_dup2(unsigned int oldfd, unsigned int newfd);
int shim_do_pause(void);
int shim_do_nanosleep(const struct __kernel_timespec* rqtp, struct __kernel_timespec* rmtp);
int shim_do_getitimer(int which, struct __kernel_itimerval* value);
int shim_do_alarm(unsigned int seconds);
int shim_do_setitimer(int which, struct __kernel_itimerval* value,
                      struct __kernel_itimerval* ovalue);
pid_t shim_do_getpid(void);
ssize_t shim_do_sendfile(int out_fd, int in_fd, off_t* offset, size_t count);
int shim_do_socket(int family, int type, int protocol);
int shim_do_connect(int sockfd, struct sockaddr* addr, int addrlen);
int shim_do_accept(int fd, struct sockaddr* addr, int* addrlen);
ssize_t shim_do_sendto(int fd, const void* buf, size_t len, int flags,
                       const struct sockaddr* dest_addr, int addrlen);
ssize_t shim_do_recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* addr,
                         int* addrlen);
int shim_do_bind(int sockfd, struct sockaddr* addr, int addrlen);
int shim_do_listen(int sockfd, int backlog);
ssize_t shim_do_sendmsg(int fd, struct msghdr* msg, int flags);
ssize_t shim_do_recvmsg(int fd, struct msghdr* msg, int flags);
int shim_do_shutdown(int sockfd, int how);
int shim_do_getsockname(int sockfd, struct sockaddr* addr, int* addrlen);
int shim_do_getpeername(int sockfd, struct sockaddr* addr, int* addrlen);
int shim_do_socketpair(int domain, int type, int protocol, int* sv);
int shim_do_setsockopt(int fd, int level, int optname, char* optval, int optlen);
int shim_do_getsockopt(int fd, int level, int optname, char* optval, int* optlen);
long shim_do_clone(unsigned long flags, unsigned long user_stack_addr, int* parent_tidptr,
                   int* child_tidptr, unsigned long tls);
long shim_do_fork(void);
long shim_do_vfork(void);
int shim_do_execve(const char* file, const char** argv, const char** envp);
noreturn int shim_do_exit(int error_code);
long shim_do_waitid(int which, pid_t id, siginfo_t* infop, int options, struct __kernel_rusage* ru);
long shim_do_wait4(pid_t pid, int* stat_addr, int options, struct __kernel_rusage* ru);
int shim_do_kill(pid_t pid, int sig);
int shim_do_uname(struct new_utsname* buf);
int shim_do_semget(key_t key, int nsems, int semflg);
int shim_do_semop(int semid, struct sembuf* sops, unsigned int nsops);
int shim_do_semctl(int semid, int semnum, int cmd, unsigned long arg);
int shim_do_msgget(key_t key, int msgflg);
int shim_do_msgsnd(int msqid, const void* msgp, size_t msgsz, int msgflg);
int shim_do_msgrcv(int msqid, void* msgp, size_t msgsz, long msgtyp, int msgflg);
int shim_do_msgctl(int msqid, int cmd, struct msqid_ds* buf);
int shim_do_fcntl(int fd, int cmd, unsigned long arg);
int shim_do_fsync(int fd);
int shim_do_fdatasync(int fd);
int shim_do_truncate(const char* path, loff_t length);
int shim_do_ftruncate(int fd, loff_t length);
size_t shim_do_getdents(int fd, struct linux_dirent* buf, size_t count);
int shim_do_getcwd(char* buf, size_t size);
int shim_do_chdir(const char* filename);
int shim_do_fchdir(int fd);
int shim_do_rename(const char* oldname, const char* newname);
int shim_do_mkdir(const char* pathname, int mode);
int shim_do_rmdir(const char* pathname);
int shim_do_creat(const char* path, mode_t mode);
int shim_do_unlink(const char* file);
int shim_do_readlink(const char* file, char* buf, int bufsize);
int shim_do_chmod(const char* filename, mode_t mode);
int shim_do_fchmod(int fd, mode_t mode);
int shim_do_chown(const char* filename, uid_t user, gid_t group);
int shim_do_fchown(int fd, uid_t user, gid_t group);
mode_t shim_do_umask(mode_t mask);
int shim_do_gettimeofday(struct __kernel_timeval* tv, struct __kernel_timezone* tz);
int shim_do_getrlimit(int resource, struct __kernel_rlimit* rlim);
int shim_do_getrusage(int who, struct __kernel_rusage* ru);
uid_t shim_do_getuid(void);
gid_t shim_do_getgid(void);
int shim_do_setuid(uid_t uid);
int shim_do_setgid(gid_t gid);
int shim_do_setgroups(int gidsetsize, gid_t* grouplist);
int shim_do_getgroups(int gidsetsize, gid_t* grouplist);
uid_t shim_do_geteuid(void);
gid_t shim_do_getegid(void);
pid_t shim_do_getppid(void);
int shim_do_setpgid(pid_t pid, pid_t pgid);
pid_t shim_do_getpgrp(void);
int shim_do_setsid(void);
int shim_do_getpgid(pid_t pid);
int shim_do_getsid(pid_t pid);
int shim_do_sigpending(__sigset_t* set, size_t sigsetsize);
int shim_do_sigaltstack(const stack_t* ss, stack_t* oss);
int shim_do_setpriority(int which, int who, int niceval);
int shim_do_getpriority(int which, int who);
int shim_do_sched_setparam(pid_t pid, struct __kernel_sched_param* param);
int shim_do_sched_getparam(pid_t pid, struct __kernel_sched_param* param);
int shim_do_sched_setscheduler(pid_t pid, int policy, struct __kernel_sched_param* param);
int shim_do_sched_getscheduler(pid_t pid);
int shim_do_sched_get_priority_max(int policy);
int shim_do_sched_get_priority_min(int policy);
int shim_do_sched_rr_get_interval(pid_t pid, struct timespec* interval);
int shim_do_sigsuspend(const __sigset_t* mask);
void* shim_do_arch_prctl(int code, void* addr);
int shim_do_setrlimit(int resource, struct __kernel_rlimit* rlim);
int shim_do_chroot(const char* filename);
long shim_do_sethostname(char* name, int len);
long shim_do_setdomainname(char* name, int len);
pid_t shim_do_gettid(void);
int shim_do_tkill(int pid, int sig);
time_t shim_do_time(time_t* tloc);
int shim_do_futex(int* uaddr, int op, int val, void* utime, int* uaddr2, int val3);
long shim_do_sched_setaffinity(pid_t pid, unsigned int cpumask_size, unsigned long* user_mask_ptr);
long shim_do_sched_getaffinity(pid_t pid, unsigned int cpumask_size, unsigned long* user_mask_ptr);
int shim_do_set_tid_address(int* tidptr);
int shim_do_semtimedop(int semid, struct sembuf* sops, unsigned int nsops,
                       const struct timespec* timeout);
int shim_do_epoll_create(int size);
size_t shim_do_getdents64(int fd, struct linux_dirent64* buf, size_t count);
int shim_do_epoll_wait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                       int timeout_ms);
int shim_do_epoll_ctl(int epfd, int op, int fd, struct __kernel_epoll_event* event);
int shim_do_clock_gettime(clockid_t which_clock, struct timespec* tp);
int shim_do_clock_getres(clockid_t which_clock, struct timespec* tp);
int shim_do_clock_nanosleep(clockid_t clock_id, int flags, const struct __kernel_timespec* rqtp,
                            struct __kernel_timespec* rmtp);
noreturn int shim_do_exit_group(int error_code);
int shim_do_tgkill(int tgid, int pid, int sig);
int shim_do_mbind(void* start, unsigned long len, int mode, unsigned long* nmask,
                  unsigned long maxnode, int flags);
int shim_do_openat(int dfd, const char* filename, int flags, int mode);
int shim_do_mkdirat(int dfd, const char* pathname, int mode);
int shim_do_newfstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags);
int shim_do_unlinkat(int dfd, const char* pathname, int flag);
int shim_do_readlinkat(int dirfd, const char* file, char* buf, int bufsize);
int shim_do_renameat(int olddfd, const char* pathname, int newdfd, const char* newname);
int shim_do_fchmodat(int dfd, const char* filename, mode_t mode);
int shim_do_fchownat(int dfd, const char* filename, uid_t user, gid_t group, int flags);
int shim_do_faccessat(int dfd, const char* filename, mode_t mode);
int shim_do_pselect6(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
                     const struct __kernel_timespec* tsp, const __sigset_t* sigmask);
int shim_do_ppoll(struct pollfd* fds, int nfds, struct timespec* tsp, const __sigset_t* sigmask,
                  size_t sigsetsize);
int shim_do_set_robust_list(struct robust_list_head* head, size_t len);
int shim_do_get_robust_list(pid_t pid, struct robust_list_head** head, size_t* len);
int shim_do_epoll_pwait(int epfd, struct __kernel_epoll_event* events, int maxevents,
                        int timeout_ms, const __sigset_t* sigmask, size_t sigsetsize);
int shim_do_accept4(int sockfd, struct sockaddr* addr, int* addrlen, int flags);
int shim_do_dup3(unsigned int oldfd, unsigned int newfd, int flags);
int shim_do_epoll_create1(int flags);
int shim_do_pipe2(int* fildes, int flags);
int shim_do_mknod(const char* pathname, mode_t mode, dev_t dev);
int shim_do_mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev);
ssize_t shim_do_recvmmsg(int sockfd, struct mmsghdr* msg, unsigned int vlen, int flags,
                         struct __kernel_timespec* timeout);
int shim_do_prlimit64(pid_t pid, int resource, const struct __kernel_rlimit64* new_rlim,
                      struct __kernel_rlimit64* old_rlim);
ssize_t shim_do_sendmmsg(int sockfd, struct mmsghdr* msg, unsigned int vlen, int flags);
int shim_do_eventfd2(unsigned int count, int flags);
int shim_do_eventfd(unsigned int count);
int shim_do_getcpu(unsigned* cpu, unsigned* node, struct getcpu_cache* unused);
long shim_do_getrandom(char* buf, size_t count, unsigned int flags);

#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM   0x0002
#define GRND_INSECURE 0x0004

#ifndef MADV_FREE
#define MADV_FREE 8
#endif
#ifdef __x86_64__
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif
#ifndef MADV_KEEPONFORK
#define MADV_KEEPONFORK 19
#endif
#else /* __x86_64__ */
#error "Unsupported platform"
#endif

#endif /* _SHIM_TABLE_H_ */
