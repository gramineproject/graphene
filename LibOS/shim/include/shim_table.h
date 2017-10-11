/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_TABLE_H_
#define _SHIM_TABLE_H_

#include <shim_types.h>
#include <shim_unistd.h>

#ifdef IN_SHIM

typedef void (*shim_fp)(void);

extern shim_fp shim_table[];

/* syscall entries */
long __shim_read (long, long , long);
long __shim_write (long, long, long);
long __shim_open (long, long , long);
long __shim_close (long);
long __shim_stat (long, long);
long __shim_fstat (long, long);
long __shim_lstat (long, long);
long __shim_poll (long, long, long);
long __shim_lseek (long, long, long);
long __shim_mmap (long, long, long, long, long, long);
long __shim_mprotect (long, long, long);
long __shim_munmap (long, long);
long __shim_brk (long);
long __shim_rt_sigaction (long, long, long, long);
long __shim_rt_sigprocmask (long, long, long);
long __shim_rt_sigreturn (long);
long __shim_ioctl (long, long, long);
long __shim_pread64 (long, long, long, long);
long __shim_pwrite64 (long, long, long, long);
long __shim_readv (long, long, long);
long __shim_writev (long, long, long);
long __shim_access (long, long);
long __shim_pipe (long);
long __shim_select (long, long, long, long, long);
long __shim_sched_yield (void);
long __shim_mremap (long, long, long, long, long);
long __shim_msync (long, long, long);
long __shim_mincore (long, long, long);
long __shim_madvise (long, long, long);
long __shim_shmget (long, long, long);
long __shim_shmat (long, long, long);
long __shim_shmctl (long, long, long);
long __shim_dup (long);
long __shim_dup2 (long, long);
long __shim_pause (void);
long __shim_nanosleep (long, long);
long __shim_getitimer (long, long);
long __shim_alarm (long);
long __shim_setitimer (long, long, long);
long __shim_getpid (void);
long __shim_sendfile (long, long, long, long);
long __shim_socket (long, long, long);
long __shim_connect (long, long, long);
long __shim_accept (long, long, long);
long __shim_sendto (long, long, long, long, long, long);
long __shim_recvfrom (long, long, long, long, long, long);
long __shim_sendmsg (long, long, long);
long __shim_recvmsg (long, long, long);
long __shim_shutdown (long, long);
long __shim_bind (long, long, long);
long __shim_listen (long, long);
long __shim_getsockname (long, long, long);
long __shim_getpeername (long, long, long);
long __shim_socketpair (long, long, long, long);
long __shim_setsockopt (long, long, long, long, long);
long __shim_getsockopt (long, long, long, long, long);
long __shim_clone (long, long, long, long, long);
long __shim_fork (void);
long __shim_vfork (void);
long __shim_execve (long, long, long);
long __shim_exit (long);
long __shim_wait4 (long, long, long, long);
long __shim_kill (long, long);
long __shim_uname (long);
long __shim_semget (long, long, long);
long __shim_semop (long, long, long);
long __shim_semctl (long, long, long, long);
long __shim_shmdt (long);
long __shim_msgget (long, long);
long __shim_msgsnd (long, long, long, long);
long __shim_msgrcv (long, long, long, long, long);
long __shim_msgctl (long, long, long);
long __shim_fcntl (long, long, long);
long __shim_flock (long, long);
long __shim_fsync (long);
long __shim_fdatasync (long);
long __shim_truncate (long, long);
long __shim_ftruncate (long, long);
long __shim_getdents (long, long, long);
long __shim_getcwd (long, long);
long __shim_chdir (long);
long __shim_fchdir (long);
long __shim_rename (long, long);
long __shim_mkdir (long, long);
long __shim_rmdir (long);
long __shim_creat (long, long);
long __shim_link (long, long);
long __shim_unlink (long);
long __shim_symlink (long, long);
long __shim_readlink (long, long, long);
long __shim_chmod (long, long);
long __shim_fchmod (long, long);
long __shim_chown (long, long, long);
long __shim_fchown (long, long, long);
long __shim_lchown (long, long, long);
long __shim_umask (long);
long __shim_gettimeofday (long, long);
long __shim_getrlimit (long, long);
long __shim_getrusage (long, long);
long __shim_sysinfo (long);
long __shim_times (long);
long __shim_ptrace (long, long, long, long);
long __shim_getuid (void);
long __shim_syslog (long, long, long);
long __shim_getgid (void);
long __shim_setuid (long);
long __shim_setgid (long);
long __shim_geteuid (void);
long __shim_getegid (void);
long __shim_setpgid (long, long);
long __shim_getppid (void);
long __shim_getpgrp (void);
long __shim_setsid (void);
long __shim_setreuid (long, long);
long __shim_setregid (long, long);
long __shim_getgroups (long, long);
long __shim_setgroups (long, long);
long __shim_setresuid (long, long, long);
long __shim_getresuid (long, long, long);
long __shim_setresgid (long, long, long);
long __shim_getresgid (long, long, long);
long __shim_getpgid (long);
long __shim_setfsuid (long);
long __shim_setfsgid (long);
long __shim_getsid (long);
long __shim_capget (long, long);
long __shim_capset (long, long);
long __shim_rt_sigpending (long, long);
long __shim_rt_sigtimedwait (long, long, long, long);
long __shim_rt_sigqueueinfo (long, long, long);
long __shim_rt_sigsuspend (long);
long __shim_sigaltstack (long, long);
long __shim_utime (long, long);
long __shim_mknod (long, long, long);
long __shim_uselib (long);
long __shim_personality (long);
long __shim_ustat (long, long);
long __shim_statfs (long, long);
long __shim_fstatfs (long, long);
long __shim_sysfs (long, long, long);
long __shim_getpriority (long, long);
long __shim_setpriority (long, long, long);
long __shim_sched_setparam (long, long);
long __shim_sched_getparam (long, long);
long __shim_sched_setscheduler (long, long, long);
long __shim_sched_getscheduler (long);
long __shim_sched_get_priority_max (long);
long __shim_sched_get_priority_min (long);
long __shim_sched_rr_get_interval (long, long);
long __shim_mlock (long, long);
long __shim_munlock (long, long);
long __shim_mlockall (long);
long __shim_munlockall (void);
long __shim_vhangup (void);
long __shim_modify_ldt (long, long, long);
long __shim_pivot_root (long, long);
long __shim__sysctl (long);
long __shim_prctl (long, long, long, long, long);
long __shim_arch_prctl (long, long);
long __shim_adjtimex (long);
long __shim_setrlimit (long, long);
long __shim_chroot (long);
long __shim_sync (void);
long __shim_acct (long);
long __shim_settimeofday (long, long);
long __shim_mount (long, long, long, long, long);
long __shim_umount2 (long, long);
long __shim_swapon (long, long);
long __shim_swapoff (long);
long __shim_reboot (long, long, long, long);
long __shim_sethostname (long, long);
long __shim_setdomainname (long, long);
long __shim_iopl (long);
long __shim_ioperm (long, long, long);
long __shim_create_module (long, long);
long __shim_init_module (long, long, long);
long __shim_delete_module (long, long);
long __shim_get_kernel_syms (long);
long __shim_query_module (long, long, long, long, long);
long __shim_quotactl (long, long, long, long);
long __shim_nfsservctl (long, long, long);
long __shim_gettid (void);
long __shim_readahead (long, long, long);
long __shim_setxattr (long, long, long, long, long);
long __shim_lsetxattr (long, long, long, long, long);
long __shim_fsetxattr (long, long, long, long, long);
long __shim_getxattr (long, long, long, long);
long __shim_lgetxattr (long, long, long, long);
long __shim_fgetxattr (long, long, long, long);
long __shim_listxattr (long, long, long);
long __shim_llistxattr (long, long, long);
long __shim_flistxattr (long, long, long);
long __shim_removexattr (long, long);
long __shim_lremovexattr (long, long);
long __shim_fremovexattr (long, long);
long __shim_tkill (long, long);
long __shim_time (long);
long __shim_futex (long, long, long, long, long, long);
long __shim_sched_setaffinity (long, long, long);
long __shim_sched_getaffinity (long, long, long);
long __shim_set_thread_area (long);
long __shim_io_setup (long, long);
long __shim_io_destroy (long);
long __shim_io_getevents (long, long, long, long, long);
long __shim_io_submit (long, long, long);
long __shim_io_cancel (long, long, long);
long __shim_get_thread_area (long);
long __shim_lookup_dcookie (long, long, long);
long __shim_epoll_create (long);
long __shim_remap_file_pages (long, long, long, long, long);
long __shim_getdents64 (long, long, long);
long __shim_set_tid_address (long);
long __shim_restart_syscall (void);
long __shim_semtimedop (long, long, long, long);
long __shim_fadvise64 (long, long, long, long);
long __shim_timer_create (long, long, long);
long __shim_timer_settime (long, long, long, long);
long __shim_timer_gettime (long, long);
long __shim_timer_getoverrun (long);
long __shim_timer_delete (long);
long __shim_clock_settime (long, long);
long __shim_clock_gettime (long, long);
long __shim_clock_getres (long, long);
long __shim_clock_nanosleep (long, long, long, long);
long __shim_exit_group (long);
long __shim_epoll_wait (long, long, long, long);
long __shim_epoll_ctl (long, long, long, long);
long __shim_tgkill (long, long, long);
long __shim_utimes (long, long);
long __shim_mbind (long, long, long, long, long, long);
long __shim_set_mempolicy (long, long, long);
long __shim_get_mempolicy (long, long, long, long, long);
long __shim_mq_open (long, long, long, long);
long __shim_mq_unlink (long);
long __shim_mq_timedsend (long, long, long, long, long);
long __shim_mq_timedreceive (long, long, long, long, long);
long __shim_mq_notify (long, long);
long __shim_mq_getsetattr (long, long, long);
long __shim_kexec_load (long, long, long, long);
long __shim_waitid (long, long, long, long, long);
long __shim_add_key (long, long, long, long, long);
long __shim_request_key (long, long, long, long);
long __shim_keyctl (long, long, long, long, long);
long __shim_ioprio_set (long, long, long);
long __shim_ioprio_get (long, long);
long __shim_inotify_init (void);
long __shim_inotify_add_watch (long, long, long);
long __shim_inotify_rm_watch (long, long);
long __shim_migrate_pages (long, long, long, long);
long __shim_openat (long, long, long, long);
long __shim_mkdirat (long, long, long);
long __shim_mknodat (long, long, long, long);
long __shim_fchownat (long, long, long, long, long);
long __shim_futimesat (long, long, long);
long __shim_newfstatat (long, long, long, long);
long __shim_unlinkat (long, long, long);
long __shim_renameat (long, long, long, long);
long __shim_linkat (long, long, long, long, long);
long __shim_symlinkat (long, long, long);
long __shim_readlinkat (long, long, long, long);
long __shim_fchmodat (long, long, long);
long __shim_faccessat (long, long, long);
long __shim_pselect6 (long, long, long, long, long, long);
long __shim_ppoll (long, long, long, long, long);
long __shim_unshare (long);
long __shim_set_robust_list (long, long);
long __shim_get_robust_list (long, long, long);
long __shim_splice (long, long, long, long, long, long);
long __shim_tee (long, long, long, long);
long __shim_sync_file_range (long, long, long, long);
long __shim_vmsplice (long, long, long, long);
long __shim_move_pages (long, long, long, long, long, long);
long __shim_utimensat (long, long, long, long);
long __shim_epoll_pwait (long, long, long, long, long, long);
long __shim_signalfd (long, long, long);
long __shim_timerfd_create (long, long);
long __shim_eventfd (long);
long __shim_fallocate (long, long, long, long);
long __shim_timerfd_settime (long, long, long, long);
long __shim_timerfd_gettime (long, long);
long __shim_accept4 (long, long, long, long);
long __shim_signalfd4 (long, long, long, long);
long __shim_eventfd2 (long, long);
long __shim_epoll_create1 (long);
long __shim_dup3 (long, long, long);
long __shim_pipe2 (long, long);
long __shim_inotify_init1 (long);
long __shim_preadv (long, long, long, long, long);
long __shim_pwritev (long, long, long, long, long);
long __shim_rt_tgsigqueueinfo (long, long, long, long);
long __shim_perf_event_open (long, long, long, long, long);
long __shim_recvmmsg (long, long, long, long, long);
long __shim_fanotify_init (long, long);
long __shim_fanotify_mark (long, long, long, long, long);
long __shim_prlimit64 (long, long, long, long);
long __shim_name_to_handle_at (long, long, long, long, long);
long __shim_open_by_handle_at (long, long, long);
long __shim_clock_adjtime (long, long);
long __shim_syncfs (long);
long __shim_sendmmsg (long, long, long, long);
long __shim_setns (long, long);
long __shim_getcpu (long, long, long);

/* libos call entries */
long __shim_sandbox_create (long, long, long);
long __shim_sandbox_attach (long);
long __shim_sandbox_current (void);
long __shim_msgpersist (long, long);
long __shim_benchmark_rpc (long, long, long, long);
long __shim_send_rpc (long, long, long);
long __shim_recv_rpc (long, long, long);
long __shim_checkpoint(long);

/* syscall implementation */
size_t shim_do_read (int fd, void * buf, size_t count);
size_t shim_do_write (int fd, const void * buf, size_t count);
int shim_do_open (const char * file, int flags, mode_t mode);
int shim_do_close (int fd);
int shim_do_stat (const char * file, struct stat * statbuf);
int shim_do_fstat (int fd, struct stat * statbuf);
int shim_do_lstat (const char * file, struct stat * stat);
int shim_do_poll (struct pollfd * fds, nfds_t nfds, int timeout);
off_t shim_do_lseek (int fd, off_t offset, int origin);
void * shim_do_mmap (void * addr, size_t length, int prot, int flags, int fd,
                     off_t offset);
int shim_do_mprotect (void * addr, size_t len, int prot);
int shim_do_munmap (void * addr, size_t len);
void * shim_do_brk (void * brk);
int shim_do_sigaction (int signum, const struct __kernel_sigaction * act,
                       struct __kernel_sigaction * oldact, size_t sigsetsize);
int shim_do_sigprocmask (int how, const __sigset_t * set, __sigset_t * oldset);
int shim_do_sigreturn (int __unused);
int shim_do_ioctl (int fd, int cmd, unsigned long arg);
size_t shim_do_pread64 (int fd, char * buf, size_t count, loff_t pos);
size_t shim_do_pwrite64 (int fd, char * buf,  size_t count, loff_t pos);
ssize_t shim_do_readv (int fd, const struct iovec * vec, int vlen);
ssize_t shim_do_writev (int fd, const struct iovec * vec, int vlen);
int shim_do_access (const char * file, mode_t mode);
int shim_do_pipe (int * fildes);
int shim_do_select (int nfds, fd_set * readfds, fd_set * writefds,
                    fd_set * errorfds, struct __kernel_timeval * timeout);
int shim_do_sched_yield (void);
void * shim_do_mremap (void * addr, size_t old_len, size_t new_len,
                       int flags, void * new_addr);
int shim_do_msync (void * start, size_t len, int flags);
int shim_do_dup (int fd);
int shim_do_dup2 (int oldfd, int newfd);
int shim_do_pause (void);
int shim_do_nanosleep (const struct __kernel_timespec * rqtp,
                       struct __kernel_timespec * rmtp);
int shim_do_getitimer (int which, struct __kernel_itimerval * value);
int shim_do_alarm (unsigned int seconds);
int shim_do_setitimer (int which, struct __kernel_itimerval * value,
                       struct __kernel_itimerval * ovalue);
pid_t shim_do_getpid (void);
ssize_t shim_do_sendfile (int out_fd, int in_fd, off_t * offset, size_t count);
int shim_do_socket (int family, int type, int protocol);
int shim_do_connect (int sockfd, struct sockaddr * addr, int addrlen);
int shim_do_accept (int fd, struct sockaddr * addr, socklen_t * addrlen);
ssize_t shim_do_sendto (int fd, const void * buf, size_t len, int flags,
                        const struct sockaddr * dest_addr, socklen_t addrlen);
ssize_t shim_do_recvfrom (int fd, void * buf, size_t len, int flags,
                          struct sockaddr * addr, socklen_t * addrlen);
int shim_do_bind (int sockfd, struct sockaddr * addr, socklen_t addrlen);
int shim_do_listen (int sockfd, int backlog);
ssize_t shim_do_sendmsg (int fd, struct msghdr * msg, int flags);
ssize_t shim_do_recvmsg (int fd, struct msghdr * msg, int flags);
int shim_do_shutdown (int sockfd, int how);
int shim_do_getsockname (int sockfd, struct sockaddr * addr, int * addrlen);
int shim_do_getpeername (int sockfd, struct sockaddr * addr, int * addrlen);
int shim_do_socketpair (int domain, int type, int protocol, int * sv);
int shim_do_setsockopt (int fd, int level, int optname, char * optval,
                        int optlen);
int shim_do_getsockopt (int fd, int level, int optname, char * optval,
                        int * optlen);
int shim_do_clone (int flags, void * user_stack_addr, int * parent_tidptr,
                   int * child_tidptr, void * tls);
int shim_do_fork (void);
int shim_do_vfork (void);
int shim_do_execve (const char * file, const char ** argv, const char ** envp);
int shim_do_exit (int error_code);
pid_t shim_do_wait4 (pid_t pid, int * stat_addr, int option,
                     struct __kernel_rusage * ru);
int shim_do_kill (pid_t pid, int sig);
int shim_do_uname (struct old_utsname * buf);
int shim_do_semget (key_t key, int nsems, int semflg);
int shim_do_semop (int semid, struct sembuf * sops, unsigned int nsops);
int shim_do_semctl (int semid, int semnum, int cmd, unsigned long arg);
int shim_do_msgget (key_t key, int msgflg);
int shim_do_msgsnd ( int msqid, const void * msgp, size_t msgsz, int msgflg);
int shim_do_msgrcv (int msqid, void * msgp, size_t msgsz, long msgtyp,
                    int msgflg);
int shim_do_msgctl (int msqid, int cmd, struct msqid_ds * buf);
int shim_do_fcntl (int fd, int cmd, unsigned long arg);
int shim_do_fsync (int fd);
int shim_do_fdatasync (int fd);
int shim_do_truncate (const char * path, loff_t length);
int shim_do_ftruncate (int fd, loff_t length);
size_t shim_do_getdents (int fd, struct linux_dirent * buf, size_t count);
int shim_do_getcwd (char *buf, size_t size);
int shim_do_chdir (const char * filename);
int shim_do_fchdir (int fd);
int shim_do_rename (const char * oldname, const char * newname);
int shim_do_mkdir (const char * pathname, int mode);
int shim_do_rmdir (const char * pathname);
int shim_do_creat (const char * path, mode_t mode);
int shim_do_unlink (const char * file);
int shim_do_readlink (const char * file, char * buf, int bufsize);
int shim_do_chmod (const char * filename, mode_t mode);
int shim_do_fchmod (int fd, mode_t mode);
int shim_do_chown (const char * filename, uid_t user, gid_t group);
int shim_do_fchown (int fd, uid_t user, gid_t group);
mode_t shim_do_umask (mode_t mask);
int shim_do_gettimeofday (struct __kernel_timeval * tv,
                          struct __kernel_timezone * tz);
int shim_do_getrlimit (int resource, struct __kernel_rlimit * rlim);
uid_t shim_do_getuid (void);
gid_t shim_do_getgid (void);
int shim_do_setuid (uid_t uid);
int shim_do_setgid (gid_t gid);
uid_t shim_do_geteuid (void);
gid_t shim_do_getegid (void);
pid_t shim_do_getppid (void);
int shim_do_setpgid (pid_t pid, pid_t pgid);
pid_t shim_do_getpgrp (void);
int shim_do_setsid (void);
int shim_do_getpgid (pid_t pid);
int shim_do_getsid (pid_t pid);
int shim_do_sigpending (__sigset_t * set, size_t sigsetsize);
int shim_do_sigaltstack (const stack_t * ss, stack_t * oss);
int shim_do_sigsuspend (const __sigset_t * mask);
void * shim_do_arch_prctl (int code, void * addr);
int shim_do_setrlimit (int resource, struct __kernel_rlimit * rlim);
int shim_do_chroot (const char * filename);
pid_t shim_do_gettid (void);
int shim_do_tkill (int pid, int sig);
time_t shim_do_time (time_t * tloc);
int shim_do_futex (unsigned int * uaddr, int op, int val, void * utime,
                   unsigned int * uaddr2, int val3);
int shim_do_set_tid_address (int * tidptr);
int shim_do_semtimedop (int semid, struct sembuf * sops, unsigned int nsops,
                        const struct timespec * timeout);
int shim_do_epoll_create (int size);
size_t shim_do_getdents64 (int fd, struct linux_dirent64 * buf, size_t count);
int shim_do_epoll_wait (int epfd, struct __kernel_epoll_event * events,
                        int maxevents, int timeout);
int shim_do_epoll_ctl (int epfd, int op, int fd,
                       struct __kernel_epoll_event * event);
int shim_do_clock_gettime (clockid_t which_clock,
                           struct timespec * tp);
int shim_do_clock_getres (clockid_t which_clock,
                          struct timespec * tp);
int shim_do_exit_group (int error_code);
int shim_do_tgkill (int tgid, int pid, int sig);
int shim_do_openat (int dfd, const char * filename, int flags, int mode);
int shim_do_mkdirat (int dfd, const char * pathname, int mode);
int shim_do_unlinkat (int dfd, const char * pathname, int flag);
int shim_do_renameat (int olddfd, const char * pathname, int newdfd,
                      const char * newname);
int shim_do_fchmodat (int dfd, const char * filename, mode_t mode);
int shim_do_fchownat (int dfd, const char * filename, uid_t user, gid_t group,
                      int flags);
int shim_do_faccessat (int dfd, const char * filename, mode_t mode);
int shim_do_pselect6 (int nfds, fd_set * readfds, fd_set * writefds,
                      fd_set * exceptfds, const struct __kernel_timespec * tsp,
                      const __sigset_t * sigmask);
int shim_do_ppoll (struct pollfd * fds, int nfds, struct timespec * tsp,
                   const __sigset_t * sigmask, size_t sigsetsize);
int shim_do_set_robust_list (struct robust_list_head * head, size_t len);
int shim_do_get_robust_list (pid_t pid, struct robust_list_head ** head,
                             size_t * len);
int shim_do_epoll_pwait (int epfd, struct __kernel_epoll_event * events,
                         int maxevents, int timeout, const __sigset_t * sigmask,
                         size_t sigsetsize);
int shim_do_accept4 (int sockfd, struct sockaddr * addr, socklen_t * addrlen,
                     int flags);
int shim_do_dup3 (int oldfd, int newfd, int flags);
int shim_do_epoll_create1 (int flags);
int shim_do_pipe2 (int * fildes, int flags);
int shim_do_recvmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags,
                      struct __kernel_timespec * timeout);
int shim_do_sendmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags);

/* libos call implementation */
long shim_do_sandbox_create (int flags, const char * fs_sb,
                             struct net_sb * net_sb);
int shim_do_sandbox_attach (unsigned int sbid);
long shim_do_sandbox_current (void);
int shim_do_msgpersist (int msqid, int cmd);
int shim_do_benchmark_rpc (pid_t pid, int times, const void * buf, size_t size);
size_t shim_do_send_rpc (pid_t pid, const void * buf, size_t size);
size_t shim_do_recv_rpc (pid_t * pid, void * buf, size_t size);
int shim_do_checkpoint(const char * filename);

#endif /* ! IN_SHIM */

/* syscall wrappers */
size_t shim_read (int fd, void * buf, size_t count);
size_t shim_write (int fd, const void * buf, size_t count);
int shim_open (const char * file, int flags, mode_t mode);
int shim_close (int fd);
int shim_stat (const char * file, struct stat * statbuf);
int shim_fstat (int fd, struct stat * statbuf);
int shim_lstat (const char * file, struct stat * statbuf);
int shim_poll (struct pollfd * fds, nfds_t nfds, int timeout);
off_t shim_lseek (int fd, off_t offset, int origin);
void * shim_mmap (void * addr, size_t length, int prot, int flags, int fd,
                  off_t offset);
int shim_mprotect (void * addr, size_t len, int prot);
int shim_munmap (void * addr, size_t len);
void * shim_brk (void * brk);
int shim_rt_sigaction (int signum, const struct __kernel_sigaction * act,
                       struct __kernel_sigaction * oldact, size_t sigsetsize);
int shim_rt_sigprocmask (int how, const __sigset_t * set, __sigset_t * oldset);
int shim_rt_sigreturn (int __unused);
int shim_ioctl (int fd, int cmd, unsigned long arg);
size_t shim_pread64 (int fd, char * buf, size_t count, loff_t pos);
size_t shim_pwrite64 (int fd, char * buf, size_t count, loff_t pos);
ssize_t shim_readv (int fd, const struct iovec * vec, int vlen);
ssize_t shim_writev (int fd, const struct iovec * vec, int vlen);
int shim_access (const char * file, mode_t mode);
int shim_pipe (int * fildes);
int shim_select (int nfds, fd_set * readfds, fd_set * writefds,
                 fd_set * errorfds, struct __kernel_timeval * timeout);
int shim_sched_yield (void);
void * shim_mremap (void * addr, size_t old_len, size_t new_len, int flags,
                    void * new_addr);
int shim_msync (void * start, size_t len, int flags);
int shim_mincore (void * start, size_t len, unsigned char * vec);
int shim_madvise (void * start, size_t len, int behavior);
int shim_shmget (key_t key, size_t size, int shmflg);
void * shim_shmat (int shmid, const void * shmaddr, int shmflg);
int shim_shmctl (int shmid, int cmd, struct shmid_ds * buf);
int shim_dup (int fd);
int shim_dup2 (int oldfd, int newfd);
int shim_pause (void);
int shim_nanosleep (const struct __kernel_timespec * rqtp,
                    struct __kernel_timespec * rmtp);
int shim_getitimer (int which, struct __kernel_itimerval * value);
int shim_alarm (unsigned int seconds);
int shim_setitimer (int which, struct __kernel_itimerval * value,
                    struct __kernel_itimerval * ovalue);
pid_t shim_getpid (void);
ssize_t shim_sendfile (int out_fd, int in_fd, off_t * offset, size_t count);
int shim_socket (int family, int type, int protocol);
int shim_connect (int sockfd, struct sockaddr * addr, int addrlen);
int shim_accept (int fd, struct sockaddr * addr, socklen_t * addrlen);
ssize_t shim_sendto (int fd, const void * buf, size_t len, int flags,
                     const struct sockaddr * dest_addr, socklen_t addrlen);
ssize_t shim_recvfrom (int fd, void * buf, size_t len, int flags,
                       struct sockaddr * addr, socklen_t * addrlen);
int shim_bind (int sockfd, struct sockaddr * addr, socklen_t addrlen);
int shim_listen (int sockfd, int backlog);
ssize_t shim_sendmsg (int fd, struct msghdr * msg, int flags);
ssize_t shim_recvmsg (int fd, struct msghdr * msg, int flags);
int shim_shutdown (int sockfd, int how);
int shim_getsockname (int sockfd, struct sockaddr * addr, int * addrlen);
int shim_getpeername (int sockfd, struct sockaddr * addr, int * addrlen);
int shim_socketpair (int domain, int type, int protocol, int * sv);
int shim_setsockopt (int fd, int level, int optname, char * optval, int optlen);
int shim_getsockopt (int fd, int level, int optname, char * optval,
                     int * optlen);
int shim_clone (int flags, void * user_stack_addr, int * parent_tidptr,
                int * child_tidptr, void * tls);
int shim_fork (void);
int shim_vfork (void);
int shim_execve (const char * file, const char ** argv, const char ** envp);
int shim_exit (int error_code);
pid_t shim_wait4 (pid_t pid, int * stat_addr, int option,
                  struct __kernel_rusage * ru);
int shim_kill (pid_t pid, int sig);
int shim_uname (struct old_utsname * buf);
int shim_semget (key_t key, int nsems, int semflg);
int shim_semop (int semid, struct sembuf * sops, unsigned int nsops);
int shim_semctl (int semid, int semnum, int cmd, unsigned long arg);
int shim_shmdt (const void * shmaddr);
int shim_msgget (key_t key, int msgflg);
int shim_msgsnd (int msqid, const void * msgp, size_t msgsz, int msgflg);
int shim_msgrcv (int msqid, void * msgp, size_t msgsz, long msgtyp, int msgflg);
int shim_msgctl (int msqid, int cmd, struct msqid_ds * buf);
int shim_fcntl (int fd, int cmd, unsigned long arg);
int shim_flock (int fd, int cmd);
int shim_fsync (int fd);
int shim_fdatasync (int fd);
int shim_truncate (const char * path, loff_t length);
int shim_ftruncate (int fd, loff_t length);
size_t shim_getdents (int fd, struct linux_dirent * buf, size_t count);
int shim_getcwd (char * buf, size_t size);
int shim_chdir (const char * filename);
int shim_fchdir (int fd);
int shim_rename (const char * oldname, const char * newname);
int shim_mkdir (const char * pathname, int mode);
int shim_rmdir (const char * pathname);
int shim_creat (const char * path, mode_t mode);
int shim_link (const char * oldname, const char * newname);
int shim_unlink (const char * file);
int shim_symlink (const char * old, const char * new);
int shim_readlink (const char * file, char * buf, int bufsize);
int shim_chmod (const char * filename, mode_t mode);
int shim_fchmod (int fd, mode_t mode);
int shim_chown (const char * filename, uid_t user, gid_t group);
int shim_fchown (int fd, uid_t user, gid_t group);
int shim_lchown (const char * filename, uid_t user, gid_t group);
mode_t shim_umask (mode_t mask);
int shim_gettimeofday (struct __kernel_timeval * tv,
                       struct __kernel_timezone * tz);
int shim_getrlimit (int resource, struct __kernel_rlimit * rlim);
int shim_getrusage (int who, struct __kernel_rusage * ru);
int shim_sysinfo (struct sysinfo * info);
int shim_times (struct tms * tbuf);
int shim_ptrace (long request, pid_t pid, void * addr, void * data);
uid_t shim_getuid (void);
int shim_syslog (int type, char * buf, int len);
gid_t shim_getgid (void);
int shim_setuid (uid_t uid);
int shim_setgid (gid_t gid);
uid_t shim_geteuid (void);
gid_t shim_getegid (void);
int shim_setpgid (pid_t pid, pid_t pgid);
pid_t shim_getppid (void);
pid_t shim_getpgrp (void);
int shim_setsid (void);
int shim_setreuid (uid_t ruid, uid_t euid);
int shim_setregid (gid_t rgid, gid_t egid);
int shim_getgroups (int gidsetsize, gid_t * grouplist);
int shim_setgroups (int gidsetsize, gid_t * grouplist);
int shim_setresuid (uid_t ruid, uid_t euid, uid_t suid);
int shim_getresuid (uid_t * ruid, uid_t * euid, uid_t * suid);
int shim_setresgid (gid_t rgid, gid_t egid, gid_t sgid);
int shim_getresgid (gid_t * rgid, gid_t * egid, gid_t * sgid);
int shim_getpgid (pid_t pid);
int shim_setfsuid (uid_t uid);
int shim_setfsgid (gid_t gid);
int shim_getsid (pid_t pid);
int shim_capget (cap_user_header_t header, cap_user_data_t dataptr);
int shim_capset (cap_user_header_t header, const cap_user_data_t data);
int shim_rt_sigpending (__sigset_t * set, size_t sigsetsize);
int shim_rt_sigtimedwait (const __sigset_t * uthese, siginfo_t * uinfo,
                          const struct timespec * uts, size_t sigsetsize);
int shim_rt_sigqueueinfo (int pid, int sig, siginfo_t * uinfo);
int shim_rt_sigsuspend (const __sigset_t * mask);
int shim_sigaltstack (const stack_t * ss, stack_t * oss);
int shim_utime (char * filename, struct utimbuf * times);
int shim_mknod (const char * filename, int mode, unsigned dev);
int shim_uselib (const char * library);
int shim_personality (unsigned int personality);
int shim_ustat (unsigned dev, struct __kernel_ustat * ubuf);
int shim_statfs (const char * path, struct statfs * buf);
int shim_fstatfs (int fd, struct statfs * buf);
int shim_sysfs (int option, unsigned long arg1, unsigned long arg2);
int shim_getpriority (int which, int who);
int shim_setpriority (int which, int who, int niceval);
int shim_sched_setparam (pid_t pid, struct __kernel_sched_param * param);
int shim_sched_getparam (pid_t pid, struct __kernel_sched_param * param);
int shim_sched_setscheduler (pid_t pid, int policy,
                             struct __kernel_sched_param * param);
int shim_sched_getscheduler (pid_t pid);
int shim_sched_get_priority_max (int policy);
int shim_sched_get_priority_min (int policy);
int shim_sched_rr_get_interval (pid_t pid, struct timespec * interval);
int shim_mlock (void * start, size_t len);
int shim_munlock (void * start, size_t len);
int shim_mlockall (int flags);
int shim_munlockall (void);
int shim_vhangup (void);
int shim_modify_ldt (int func, void * ptr, unsigned long bytecount);
int shim_pivot_root (const char * new_root, const char * put_old);
int shim__sysctl (struct __kernel_sysctl_args * args);
int shim_prctl (int option, unsigned long arg2, unsigned long arg3,
                unsigned long arg4, unsigned long arg5);
void * shim_arch_prctl (int code, void * addr);
int shim_adjtimex (struct __kernel_timex * txc_p);
int shim_setrlimit (int resource, struct __kernel_rlimit * rlim);
int shim_chroot (const char * filename);
int shim_sync (void);
int shim_acct (const char * name);
int shim_settimeofday (struct timeval * tv, struct __kernel_timezone * tz);
int shim_mount (char * dev_name, char * dir_name, char * type,
                unsigned long flags, void * data);
int shim_umount2 (const char * target, int flags);
int shim_swapon (const char * specialfile, int swap_flags);
int shim_swapoff (const char * specialfile);
int shim_reboot (int magic1, int magic2, int cmd, void * arg);
int shim_sethostname (char * name, int len);
int shim_setdomainname (char * name, int len);
int shim_iopl (int level);
int shim_ioperm (unsigned long from, unsigned long num, int on);
int shim_create_module (const char * name, size_t size);
int shim_init_module (void * umod, unsigned long len, const char * uargs);
int shim_delete_module (const char * name_user, unsigned int flags);
int shim_query_module (const char * name, int which, void * buf, size_t bufsize,
                       size_t * retsize);
int shim_quotactl (int cmd, const char * special, qid_t id, void * addr);
pid_t shim_gettid (void);
int shim_readahead (int fd, loff_t offset, size_t count);
int shim_setxattr (const char * path, const char * name, const void * value,
                   size_t size, int flags);
int shim_lsetxattr (const char * path, const char * name, const void * value,
                    size_t size, int flags);
int shim_fsetxattr (int fd, const char * name, const void * value, size_t size,
                    int flags);
int shim_getxattr (const char * path, const char * name, void * value,
                   size_t size);
int shim_lgetxattr (const char * path, const char * name, void * value,
                    size_t size);
int shim_fgetxattr (int fd, const char * name, void * value, size_t size);
int shim_listxattr (const char * path, char * list, size_t size);
int shim_llistxattr (const char * path, char * list, size_t size);
int shim_flistxattr (int fd, char * list, size_t size);
int shim_removexattr (const char * path, const char * name);
int shim_lremovexattr (const char * path, const char * name);
int shim_fremovexattr (int fd, const char * name);
int shim_tkill (int pid, int sig);
time_t shim_time (time_t * tloc);
int shim_futex (unsigned int * uaddr, int op, int val, void * utime,
                unsigned int * uaddr2, int val3);
int shim_sched_setaffinity (pid_t pid, size_t len,
                            __kernel_cpu_set_t * user_mask_ptr);
int shim_sched_getaffinity (pid_t pid, size_t len,
                            __kernel_cpu_set_t * user_mask_ptr);
int shim_set_thread_area (struct user_desc * u_info);
int shim_io_setup (unsigned nr_reqs, aio_context_t * ctx);
int shim_io_destroy (aio_context_t ctx);
int shim_io_getevents (aio_context_t ctx_id, long min_nr, long nr,
                       struct io_event * events, struct timespec * timeout);
int shim_io_submit (aio_context_t ctx_id, long nr, struct iocb ** iocbpp);
int shim_io_cancel (aio_context_t ctx_id, struct iocb * iocb,
                    struct io_event * result);
int shim_get_thread_area (struct user_desc * u_info);
int shim_lookup_dcookie (unsigned long cookie64, char * buf, size_t len);
int shim_epoll_create (int size);
int shim_remap_file_pages (void * start, size_t size, int prot, ssize_t pgoff,
                           int flags);
size_t shim_getdents64 (int fd, struct linux_dirent64 * buf, size_t count);
int shim_set_tid_address (int * tidptr);
int shim_restart_syscall (void);
int shim_semtimedop (int semid, struct sembuf * sops, unsigned nsops,
                     const struct timespec * timeout);
int shim_fadvise64 (int fd, loff_t offset, size_t len, int advice);
int shim_timer_create (clockid_t which_clock,
                       struct sigevent * timer_event_spec,
                       timer_t * created_timer_id);
int shim_timer_settime (timer_t timer_id, int flags,
                        const struct __kernel_itimerspec * new_setting,
                        struct __kernel_itimerspec * old_setting);
int shim_timer_gettime (timer_t timer_id, struct __kernel_itimerspec * setting);
int shim_timer_getoverrun (timer_t timer_id);
int shim_timer_delete (timer_t timer_id);
int shim_clock_settime (clockid_t which_clock, const struct timespec * tp);
int shim_clock_gettime (clockid_t which_clock, struct timespec * tp);
int shim_clock_getres (clockid_t which_clock, struct timespec * tp);
int shim_clock_nanosleep (clockid_t which_clock, int flags,
                          const struct timespec * rqtp, struct timespec * rmtp);
int shim_exit_group (int error_code);
int shim_epoll_wait (int epfd, struct __kernel_epoll_event * events,
                     int maxevents, int timeout);
int shim_epoll_ctl (int epfd, int op, int fd,
                    struct __kernel_epoll_event * event);
int shim_tgkill (int tgid, int pid, int sig);
int shim_utimes (char * filename, struct timeval * utimes);
int shim_mbind (void * start, unsigned long len, int mode,
                unsigned long * nmask, unsigned long maxnode, int flags);
int shim_set_mempolicy (int mode, unsigned long * nmask, unsigned long maxnode);
int shim_get_mempolicy (int * policy, unsigned long * nmask,
                        unsigned long maxnode, unsigned long addr,
                        unsigned long flags);
int shim_mq_open (const char * name, int oflag, mode_t mode,
                  struct __kernel_mq_attr * attr);
int shim_mq_unlink (const char * name);
int shim_mq_timedsend (__kernel_mqd_t mqdes, const char * msg_ptr,
                       size_t msg_len, unsigned int msg_prio,
                       const struct timespec * abs_timeout);
int shim_mq_timedreceive (__kernel_mqd_t mqdes, char * msg_ptr, size_t msg_len,
                          unsigned int * msg_prio,
                          const struct timespec * abs_timeout);
int shim_mq_notify (__kernel_mqd_t mqdes, const struct sigevent * notification);
int shim_mq_getsetattr (__kernel_mqd_t mqdes,
                        const struct __kernel_mq_attr * mqstat,
                        struct __kernel_mq_attr * omqstat);
int shim_waitid (int which, pid_t pid, siginfo_t * infop, int options,
                 struct __kernel_rusage * ru);
int shim_ioprio_set (int which, int who, int ioprio);
int shim_ioprio_get (int which, int who);
int shim_inotify_init (void);
int shim_inotify_add_watch (int fd, const char * path, unsigned int mask);
int shim_inotify_rm_watch (int fd, unsigned int wd);
int shim_migrate_pages (pid_t pid, unsigned long maxnode,
                        const unsigned long * from, const unsigned long * to);
int shim_openat (int dfd, const char * filename, int flags, int mode);
int shim_mkdirat (int dfd, const char * pathname, int mode);
int shim_mknodat (int dfd, const char * filename, int mode, unsigned dev);
int shim_fchownat (int dfd, const char * filename, uid_t user, gid_t group,
                   int flag);
int shim_futimesat (int dfd, const char * filename, struct timeval * utimes);
int shim_newfstatat (int dfd, const char * filename, struct stat * statbuf,
                     int flag);
int shim_unlinkat (int dfd, const char * pathname, int flag);
int shim_renameat (int olddfd, const char * oldname, int newdfd,
                   const char * newname);
int shim_linkat (int olddfd, const char * oldname, int newdfd,
                 const char * newname, int flags);
int shim_symlinkat (const char * oldname, int newdfd, const char * newname);
int shim_readlinkat (int dfd, const char * path, char * buf, int bufsiz);
int shim_fchmodat (int dfd, const char * filename, mode_t mode);
int shim_faccessat (int dfd, const char * filename, int mode);
int shim_pselect6 (int nfds, fd_set * readfds, fd_set * writefds,
                   fd_set * exceptfds, const struct __kernel_timespec * tsp,
                   const __sigset_t * sigmask);
int shim_ppoll (struct pollfd * fds, int nfds, struct timespec * tsp,
                const __sigset_t * sigmask, size_t sigsetsize);
int shim_unshare (int unshare_flags);
int shim_set_robust_list (struct robust_list_head * head, size_t len);
int shim_get_robust_list (pid_t pid, struct robust_list_head ** head,
                          size_t * len);
int shim_splice (int fd_in, loff_t * off_in, int fd_out, loff_t * off_out,
                 size_t len, int flags);
int shim_tee (int fdin, int fdout, size_t len, unsigned int flags);
int shim_sync_file_range (int fd, loff_t offset, loff_t nbytes, int flags);
int shim_vmsplice (int fd, const struct iovec * iov, unsigned long nr_segs,
                   int flags);
int shim_move_pages (pid_t pid, unsigned long nr_pages, void ** pages,
                     const int * nodes, int * status, int flags);
int shim_utimensat (int dfd, const char * filename, struct timespec *
                    utimes, int flags);
int shim_epoll_pwait (int epfd, struct __kernel_epoll_event * events,
                      int maxevents, int timeout, const __sigset_t * sigmask,
                      size_t sigsetsize);
int shim_signalfd (int ufd, __sigset_t * user_mask, size_t sizemask);
int shim_timerfd_create (int clockid, int flags);
int shim_eventfd (int count);
int shim_fallocate (int fd, int mode, loff_t offset, loff_t len);
int shim_timerfd_settime (int ufd, int flags,
                          const struct __kernel_itimerspec * utmr,
                          struct __kernel_itimerspec * otmr);
int shim_timerfd_gettime (int ufd, struct __kernel_itimerspec * otmr);
int shim_accept4 (int sockfd, struct sockaddr * addr, socklen_t * addrlen,
                  int flags);
int shim_signalfd4 (int ufd, __sigset_t * user_mask, size_t sizemask, int flags);
int shim_eventfd2 (int count, int flags);
int shim_epoll_create1 (int flags);
int shim_dup3 (int oldfd, int newfd, int flags);
int shim_pipe2 (int * fildes, int flags);
int shim_inotify_init1 (int flags);
int shim_preadv (unsigned long fd, const struct iovec * vec,
                 unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
int shim_pwritev (unsigned long fd, const struct iovec * vec,
                  unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
int shim_rt_tgsigqueueinfo (pid_t tgid, pid_t pid, int sig, siginfo_t * uinfo);
int shim_perf_event_open (struct perf_event_attr * attr_uptr, pid_t pid,
                          int cpu, int group_fd, int flags);
int shim_recvmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags,
                   struct __kernel_timespec * timeout);
int shim_sendmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags);

/* libos call wrappers */
long shim_sandbox_create (int flags, const char * fs_sb, struct net_sb * net_sb);
int shim_sandbox_attach (unsigned int sbid);
long shim_sandbox_current (void);
int shim_msgpersist (int msqid, int cmd);
int shim_benchmark_rpc (pid_t pid, int times, const void * buf, size_t size);
size_t shim_send_rpc (pid_t pid, const void * buf, size_t size);
size_t shim_recv_rpc (pid_t * pid, void * buf, size_t size);
int shim_checkpoint(const char * filename);

#endif /* _SHIM_TABLE_H_ */
