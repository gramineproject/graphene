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
 * shim_syscalls.c
 *
 * This file contains macros to redirect all system calls to the system call
 * table in library OS.
 */

#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_tcb.h>
#include <shim_unistd.h>
#include <shim_utils.h>

long int if_call_defined(long int sys_no) {
    return shim_table[sys_no] != 0;
}

DEFINE_PROFILE_CATEGORY(syscall, );

//////////////////////////////////////////////////
//  Mappings from system calls to shim calls
///////////////////////////////////////////////////

/*
  Missing, but need to be added:
  * clone
  * semctl

  from 'man unimplemented':
  NOT IMPLEMENTED in kernel (always return -ENOSYS)

  NAME
  afs_syscall,  break,  ftime,  getpmsg, gtty, lock, madvise1, mpx, prof,
  profil, putpmsg, security, stty, tuxcall, ulimit,  vserver  -
  unimplemented system calls

  SYNOPSIS
  Unimplemented system calls.

  DESCRIPTION
  These system calls are not implemented in the Linux 2.6.22 kernel.

  RETURN VALUE
  These system calls always return -1 and set errno to ENOSYS.

  NOTES
  Note  that ftime(3), profil(3) and ulimit(3) are implemented as library
  functions.

  Some system calls,  like  alloc_hugepages(2),  free_hugepages(2),  ioperm(2),
  iopl(2), and vm86(2) only exist on certain architectures.

  Some  system  calls, like ipc(2), create_module(2), init_module(2), and
  delete_module(2) only exist when the Linux kernel was built  with  support
  for them.

  SEE ALSO
  syscalls(2)

  COLOPHON
  This  page  is  part of release 3.24 of the Linux man-pages project.  A
  description of the project, and information about reporting  bugs,  can
  be found at http://www.kernel.org/doc/man-pages/.

  Linux                            2007-07-05                  UNIMPLEMENTED(2)



  Also missing from shim:
  * epoll_ctl_old
  * epoll_wait_old


  According to kernel man pages, glibc does not provide wrappers for
  every system call (append to this list as you come accross more):
  * io_setup
  * ioprio_get
  * ioprio_set
  * sysctl
  * getdents
  * tkill
  * tgkill


  Also not in libc (append to this list as you come accross more):

  * add_key: (removed in Changelog.17)
  * request_key: (removed in Changelog.17)
  * keyctl: (removed in Changelog.17)
  Although these are Linux system calls, they are not present in
  libc but can be found rather in libkeyutils. When linking,
  -lkeyutils should be specified to the linker.x

  There are probably other things of note, so put them here as you
  come across them.

*/

/* Please move implemented system call to sys/ directory and name them as the
 * most important system call */

/* read: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(read, 3, shim_do_read, size_t, int, fd, void*, buf, size_t, count)

/* write: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(write, 3, shim_do_write, size_t, int, fd, const void*, buf, size_t, count)

/* open: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(open, 3, shim_do_open, int, const char*, file, int, flags, mode_t, mode)

/* close: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(close, 1, shim_do_close, int, int, fd)

/* stat: sys/shim_stat.c */
DEFINE_SHIM_SYSCALL(stat, 2, shim_do_stat, int, const char*, file, struct stat*, statbuf)

/* fstat: sys/shim_stat.c */
DEFINE_SHIM_SYSCALL(fstat, 2, shim_do_fstat, int, int, fd, struct stat*, statbuf)

/* lstat: sys/shim_lstat.c */
/* for now we don't support symbolic link, so lstat will work exactly the same
   as stat. */
DEFINE_SHIM_SYSCALL(lstat, 2, shim_do_lstat, int, const char*, file, struct stat*, statbuf)

/* poll: sys/shim_poll.c */
DEFINE_SHIM_SYSCALL(poll, 3, shim_do_poll, int, struct pollfd*, fds, nfds_t, nfds, int, timeout)

/* lseek: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(lseek, 3, shim_do_lseek, off_t, int, fd, off_t, offset, int, origin)

/* mmap: sys/shim_mmap.c */
DEFINE_SHIM_SYSCALL(mmap, 6, shim_do_mmap, void*, void*, addr, size_t, length, int, prot, int,
                    flags, int, fd, off_t, offset)

/* mprotect: sys/shim_mmap.c */
DEFINE_SHIM_SYSCALL(mprotect, 3, shim_do_mprotect, int, void*, addr, size_t, len, int, prot)

/* munmap: sys/shim_mmap.c */
DEFINE_SHIM_SYSCALL(munmap, 2, shim_do_munmap, int, void*, addr, size_t, len)

DEFINE_SHIM_SYSCALL(brk, 1, shim_do_brk, void*, void*, brk)

/* rt_sigaction: sys/shim_sigaction.c */
DEFINE_SHIM_SYSCALL(rt_sigaction, 4, shim_do_sigaction, int, int, signum,
                    const struct __kernel_sigaction*, act, struct __kernel_sigaction*, oldact,
                    size_t, sigsetsize)

/* rt_sigprocmask: sys/shim_sigaction.c */
DEFINE_SHIM_SYSCALL(rt_sigprocmask, 3, shim_do_sigprocmask, int, int, how, const __sigset_t*, set,
                    __sigset_t*, oldset)

/* rt_sigreturn: sys/shim_sigaction.c */
DEFINE_SHIM_SYSCALL(rt_sigreturn, 1, shim_do_sigreturn, int, int, __unused)

/* ioctl: sys/shim_ioctl.c */
DEFINE_SHIM_SYSCALL(ioctl, 3, shim_do_ioctl, int, int, fd, unsigned long, cmd, unsigned long, arg)

/* pread64 : sys/shim_open.c */
DEFINE_SHIM_SYSCALL(pread64, 4, shim_do_pread64, size_t, int, fd, char*, buf, size_t, count, loff_t,
                    pos)

/* pwrite64 : sys/shim_open.c */
DEFINE_SHIM_SYSCALL(pwrite64, 4, shim_do_pwrite64, size_t, int, fd, char*, buf, size_t, count,
                    loff_t, pos)

/* readv : sys/shim_wrappers.c */
DEFINE_SHIM_SYSCALL(readv, 3, shim_do_readv, ssize_t, int, fd, const struct iovec*, vec, int, vlen)

/* writev : sys/shim_wrappers.c */
DEFINE_SHIM_SYSCALL(writev, 3, shim_do_writev, ssize_t, int, fd, const struct iovec*, vec, int,
                    vlen)

/* access: sys/shim_access.c */
DEFINE_SHIM_SYSCALL(access, 2, shim_do_access, int, const char*, file, mode_t, mode)

/* pipe: sys/shim_pipe.c */
DEFINE_SHIM_SYSCALL(pipe, 1, shim_do_pipe, int, int*, fildes)

/* select : sys/shim_poll.c*/
DEFINE_SHIM_SYSCALL(select, 5, shim_do_select, int, int, nfds, fd_set*, readfds, fd_set*, writefds,
                    fd_set*, errorfds, struct __kernel_timeval*, timeout)

/* sched_yield: sys/shim_sched.c */
DEFINE_SHIM_SYSCALL(sched_yield, 0, shim_do_sched_yield, int)

SHIM_SYSCALL_PASSTHROUGH(mremap, 5, void*, void*, addr, size_t, old_len, size_t, new_len, int,
                         flags, void*, new_addr)

SHIM_SYSCALL_PASSTHROUGH(msync, 3, int, void*, start, size_t, len, int, flags)

/* mincore: sys/shim_mmap.c */
DEFINE_SHIM_SYSCALL(mincore, 3, shim_do_mincore, int, void*, start, size_t, len, unsigned char*,
                    vec)

SHIM_SYSCALL_PASSTHROUGH(madvise, 3, int, void*, start, size_t, len, int, behavior)

SHIM_SYSCALL_PASSTHROUGH(shmget, 3, int, key_t, key, size_t, size, int, shmflg)

SHIM_SYSCALL_PASSTHROUGH(shmat, 3, void*, int, shmid, const void*, shmaddr, int, shmflg)

SHIM_SYSCALL_PASSTHROUGH(shmctl, 3, int, int, shmid, int, cmd, struct shmid_ds*, buf)

/* dup: sys/shim_dup.c */
DEFINE_SHIM_SYSCALL(dup, 1, shim_do_dup, int, int, fd)

/* dup2: sys/shim_dup.c */
DEFINE_SHIM_SYSCALL(dup2, 2, shim_do_dup2, int, int, oldfd, int, newfd)

/* pause: sys/shim_sleep.c */
DEFINE_SHIM_SYSCALL(pause, 0, shim_do_pause, int)

/* nanosleep: sys/shim_sleep.c */
DEFINE_SHIM_SYSCALL(nanosleep, 2, shim_do_nanosleep, int, const struct __kernel_timespec*, rqtp,
                    struct __kernel_timespec*, rmtp)

/* getitimer: sys/shim_alarm.c */
DEFINE_SHIM_SYSCALL(getitimer, 2, shim_do_getitimer, int, int, which, struct __kernel_itimerval*,
                    value)

/* alarm: sys/shim_alarm.c */
DEFINE_SHIM_SYSCALL(alarm, 1, shim_do_alarm, int, unsigned int, seconds)

/* setitimer: sys/shim_alarm.c */
DEFINE_SHIM_SYSCALL(setitimer, 3, shim_do_setitimer, int, int, which, struct __kernel_itimerval*,
                    value, struct __kernel_itimerval*, ovalue)

/* getpid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getpid, 0, shim_do_getpid, pid_t)

/* sendfile: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(sendfile, 4, shim_do_sendfile, ssize_t, int, out_fd, int, in_fd, off_t*, offset,
                    size_t, count)

/* socket: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(socket, 3, shim_do_socket, int, int, family, int, type, int, protocol)

/* connect: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(connect, 3, shim_do_connect, int, int, sockfd, struct sockaddr*, addr, int,
                    addrlen)

/* accept: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(accept, 3, shim_do_accept, int, int, fd, struct sockaddr*, addr, socklen_t*,
                    addrlen)

/* sendto: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(sendto, 6, shim_do_sendto, ssize_t, int, fd, const void*, buf, size_t, len, int,
                    flags, const struct sockaddr*, dest_addr, socklen_t, addrlen)

/* recvfrom : sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(recvfrom, 6, shim_do_recvfrom, ssize_t, int, fd, void*, buf, size_t, len, int,
                    flags, struct sockaddr*, addr, socklen_t*, addrlen)

/* bind: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(bind, 3, shim_do_bind, int, int, sockfd, struct sockaddr*, addr, socklen_t,
                    addrlen)

/* listen: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(listen, 2, shim_do_listen, int, int, sockfd, int, backlog)

/* sendmsg: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(sendmsg, 3, shim_do_sendmsg, ssize_t, int, fd, struct msghdr*, msg, int, flags)

/* recvmsg: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(recvmsg, 3, shim_do_recvmsg, ssize_t, int, fd, struct msghdr*, msg, int, flags)

/* shutdown: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(shutdown, 2, shim_do_shutdown, int, int, sockfd, int, how)

/* getsockname: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(getsockname, 3, shim_do_getsockname, int, int, sockfd, struct sockaddr*, addr,
                    int*, addrlen)

/* getpeername: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(getpeername, 3, shim_do_getpeername, int, int, sockfd, struct sockaddr*, addr,
                    int*, addrlen)

/* socketpair: sys/shim_pipe.c */
DEFINE_SHIM_SYSCALL(socketpair, 4, shim_do_socketpair, int, int, domain, int, type, int, protocol,
                    int*, sv)

/* setsockopt: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(setsockopt, 5, shim_do_setsockopt, int, int, fd, int, level, int, optname,
                    char*, optval, int, optlen)

/* getsockopt: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(getsockopt, 5, shim_do_getsockopt, int, int, fd, int, level, int, optname,
                    char*, optval, int*, optlen)

/* clone: sys/shim_clone.c */
DEFINE_SHIM_SYSCALL(clone, 5, shim_do_clone, int, int, flags, void*, user_stack_addr, int*,
                    parent_tidptr, int*, child_tidptr, void*, tls)

/* fork: sys/shim_fork.c */
DEFINE_SHIM_SYSCALL(fork, 0, shim_do_fork, int)

/* vfork: sys/shim_vfork.c */
DEFINE_SHIM_SYSCALL(vfork, 0, shim_do_vfork, int)

/* execve: sys/shim_exec.c */
DEFINE_SHIM_SYSCALL(execve, 3, shim_do_execve, int, const char*, file, const char**, argv,
                    const char**, envp)

/* exit: sys/shim_exit.c */
DEFINE_SHIM_SYSCALL(exit, 1, shim_do_exit, int, int, error_code)

/* wait4: sys/shim_wait.c */
DEFINE_SHIM_SYSCALL(wait4, 4, shim_do_wait4, pid_t, pid_t, pid, int*, stat_addr, int, option,
                    struct __kernel_rusage*, ru)

/* kill: sys/shim_sigaction.c */
DEFINE_SHIM_SYSCALL(kill, 2, shim_do_kill, int, pid_t, pid, int, sig)

/* uname: sys/shim_uname.c */
DEFINE_SHIM_SYSCALL(uname, 1, shim_do_uname, int, struct old_utsname*, buf)

/* semget: sys/shim_semget.c */
DEFINE_SHIM_SYSCALL(semget, 3, shim_do_semget, int, key_t, key, int, nsems, int, semflg)

/* semop: sys/shim_semget.c */
DEFINE_SHIM_SYSCALL(semop, 3, shim_do_semop, int, int, semid, struct sembuf*, sops, unsigned int,
                    nsops)

/* semctl: sys/shim_semctl.c */
DEFINE_SHIM_SYSCALL(semctl, 4, shim_do_semctl, int, int, semid, int, semnum, int, cmd,
                    unsigned long, arg)

SHIM_SYSCALL_PASSTHROUGH(shmdt, 1, int, const void*, shmaddr)

/* msgget: sys/shim_msgget.c */
DEFINE_SHIM_SYSCALL(msgget, 2, shim_do_msgget, int, key_t, key, int, msgflg)

/* msgsnd: sys/shim_msgget.c */
DEFINE_SHIM_SYSCALL(msgsnd, 4, shim_do_msgsnd, int, int, msqid, const void*, msgp, size_t, msgsz,
                    int, msgflg)

/* msgrcv: sys/shim_msgget.c */
DEFINE_SHIM_SYSCALL(msgrcv, 5, shim_do_msgrcv, int, int, msqid, void*, msgp, size_t, msgsz, long,
                    msgtyp, int, msgflg)

/* msgctl: sys/shim_msgget.c */
DEFINE_SHIM_SYSCALL(msgctl, 3, shim_do_msgctl, int, int, msqid, int, cmd, struct msqid_ds*, buf)

/* fcntl: sys/shim_fcntl.c */
DEFINE_SHIM_SYSCALL(fcntl, 3, shim_do_fcntl, int, int, fd, int, cmd, unsigned long, arg)

SHIM_SYSCALL_PASSTHROUGH(flock, 2, int, int, fd, int, cmd)

/* fsync: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(fsync, 1, shim_do_fsync, int, int, fd)

/* fdatasync: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(fdatasync, 1, shim_do_fdatasync, int, int, fd)

/* truncate: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(truncate, 2, shim_do_truncate, int, const char*, path, loff_t, length)

/* ftruncate: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(ftruncate, 2, shim_do_ftruncate, int, int, fd, loff_t, length)

/* getdents: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(getdents, 3, shim_do_getdents, size_t, int, fd, struct linux_dirent*, buf,
                    size_t, count)

/* getcwd: sys/shim_getcwd.c */
DEFINE_SHIM_SYSCALL(getcwd, 2, shim_do_getcwd, int, char*, buf, size_t, size)

/* chdir: sys/shim_getcwd.c */
DEFINE_SHIM_SYSCALL(chdir, 1, shim_do_chdir, int, const char*, filename)

/* fchdir: sys/shim_getcwd.c */
DEFINE_SHIM_SYSCALL(fchdir, 1, shim_do_fchdir, int, int, fd)

/* rename: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(rename, 2, shim_do_rename, int, const char*, oldname, const char*, newname)

/* mkdir: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(mkdir, 2, shim_do_mkdir, int, const char*, pathname, int, mode)

/* rmdir: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(rmdir, 1, shim_do_rmdir, int, const char*, pathname)

DEFINE_SHIM_SYSCALL(creat, 2, shim_do_creat, int, const char*, path, mode_t, mode)

SHIM_SYSCALL_PASSTHROUGH(link, 2, int, const char*, oldname, const char*, newname)

/* unlink: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(unlink, 1, shim_do_unlink, int, const char*, file)

SHIM_SYSCALL_PASSTHROUGH(symlink, 2, int, const char*, old, const char*, new)

/* readlink: sys/shim_stat.c */
DEFINE_SHIM_SYSCALL(readlink, 3, shim_do_readlink, int, const char*, path, char*, buf, size_t,
                    bufsize)

DEFINE_SHIM_SYSCALL(chmod, 2, shim_do_chmod, int, const char*, filename, mode_t, mode)

DEFINE_SHIM_SYSCALL(fchmod, 2, shim_do_fchmod, int, int, fd, mode_t, mode)

DEFINE_SHIM_SYSCALL(chown, 3, shim_do_chown, int, const char*, filename, uid_t, user, gid_t, group)

DEFINE_SHIM_SYSCALL(fchown, 3, shim_do_fchown, int, int, fd, uid_t, user, gid_t, group)

SHIM_SYSCALL_PASSTHROUGH(lchown, 3, int, const char*, filename, uid_t, user, gid_t, group)

DEFINE_SHIM_SYSCALL(umask, 1, shim_do_umask, mode_t, mode_t, mask)

DEFINE_SHIM_SYSCALL(gettimeofday, 2, shim_do_gettimeofday, int, struct __kernel_timeval*, tv,
                    struct __kernel_timezone*, tz)

/* getrlimit: sys/shim_getrlimit.c */
DEFINE_SHIM_SYSCALL(getrlimit, 2, shim_do_getrlimit, int, int, resource, struct __kernel_rlimit*,
                    rlim)

int shim_do_getrusage(int who, struct __kernel_rusage* ru) {
    __UNUSED(who);
    memset(ru, 0, sizeof(struct __kernel_rusage));
    return -ENOSYS;
}

DEFINE_SHIM_SYSCALL(getrusage, 2, shim_do_getrusage, int, int, who, struct __kernel_rusage*, ru)

SHIM_SYSCALL_PASSTHROUGH(sysinfo, 1, int, struct sysinfo*, info)

SHIM_SYSCALL_PASSTHROUGH(times, 1, int, struct tms*, tbuf)

SHIM_SYSCALL_PASSTHROUGH(ptrace, 4, int, long, request, pid_t, pid, void*, addr, void*, data)

/* getuid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getuid, 0, shim_do_getuid, uid_t)

SHIM_SYSCALL_PASSTHROUGH(syslog, 3, int, int, type, char*, buf, int, len)

/* getgid: sys/shim_getgid.c */
DEFINE_SHIM_SYSCALL(getgid, 0, shim_do_getgid, gid_t)

/* setuid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(setuid, 1, shim_do_setuid, int, uid_t, uid)

/* setgid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(setgid, 1, shim_do_setgid, int, gid_t, gid)

/* setgroups: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(setgroups, 2, shim_do_setgroups, int, int, gidsetsize, gid_t*, grouplist)

/* getgroups: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getgroups, 2, shim_do_getgroups, int, int, gidsetsize, gid_t*, grouplist)

/* geteuid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(geteuid, 0, shim_do_geteuid, uid_t)

/* getegid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getegid, 0, shim_do_getegid, gid_t)

/* getpgid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(setpgid, 2, shim_do_setpgid, int, pid_t, pid, pid_t, pgid)

/* getppid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getppid, 0, shim_do_getppid, pid_t)

/* getpgrp: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(getpgrp, 0, shim_do_getpgrp, pid_t)

/* setsid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(setsid, 0, shim_do_setsid, int)

SHIM_SYSCALL_PASSTHROUGH(setreuid, 2, int, uid_t, ruid, uid_t, euid)

SHIM_SYSCALL_PASSTHROUGH(setregid, 2, int, gid_t, rgid, gid_t, egid)

SHIM_SYSCALL_PASSTHROUGH(setresuid, 3, int, uid_t, ruid, uid_t, euid, uid_t, suid)

SHIM_SYSCALL_PASSTHROUGH(getresuid, 3, int, uid_t*, ruid, uid_t*, euid, uid_t*, suid)

SHIM_SYSCALL_PASSTHROUGH(setresgid, 3, int, gid_t, rgid, gid_t, egid, gid_t, sgid)

SHIM_SYSCALL_PASSTHROUGH(getresgid, 3, int, gid_t*, rgid, gid_t*, egid, gid_t*, sgid)

DEFINE_SHIM_SYSCALL(getpgid, 1, shim_do_getpgid, int, pid_t, pid)

SHIM_SYSCALL_PASSTHROUGH(setfsuid, 1, int, uid_t, uid)

SHIM_SYSCALL_PASSTHROUGH(setfsgid, 1, int, gid_t, gid)

DEFINE_SHIM_SYSCALL(getsid, 1, shim_do_getsid, int, pid_t, pid)

SHIM_SYSCALL_PASSTHROUGH(capget, 2, int, cap_user_header_t, header, cap_user_data_t, dataptr)

SHIM_SYSCALL_PASSTHROUGH(capset, 2, int, cap_user_header_t, header, const cap_user_data_t, data)

DEFINE_SHIM_SYSCALL(rt_sigpending, 2, shim_do_sigpending, int, __sigset_t*, set, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(rt_sigtimedwait, 4, int, const __sigset_t*, uthese, siginfo_t*, uinfo,
                         const struct timespec*, uts, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(rt_sigqueueinfo, 3, int, int, pid, int, sig, siginfo_t*, uinfo)

DEFINE_SHIM_SYSCALL(rt_sigsuspend, 1, shim_do_sigsuspend, int, const __sigset_t*, mask)

DEFINE_SHIM_SYSCALL(sigaltstack, 2, shim_do_sigaltstack, int, const stack_t*, ss, stack_t*, oss)

SHIM_SYSCALL_PASSTHROUGH(utime, 2, int, char*, filename, struct utimbuf*, times)

SHIM_SYSCALL_PASSTHROUGH(mknod, 3, int, const char*, filename, int, mode, unsigned, dev)

SHIM_SYSCALL_PASSTHROUGH(uselib, 1, int, const char*, library)

SHIM_SYSCALL_PASSTHROUGH(personality, 1, int, unsigned int, personality)

SHIM_SYSCALL_PASSTHROUGH(ustat, 2, int, unsigned, dev, struct __kernel_ustat*, ubuf)

SHIM_SYSCALL_PASSTHROUGH(statfs, 2, int, const char*, path, struct statfs*, buf)

SHIM_SYSCALL_PASSTHROUGH(fstatfs, 2, int, int, fd, struct statfs*, buf)

SHIM_SYSCALL_PASSTHROUGH(sysfs, 3, int, int, option, unsigned long, arg1, unsigned long, arg2)

DEFINE_SHIM_SYSCALL(setpriority, 3, shim_do_setpriority, int, int, which, int, who, int, niceval)

DEFINE_SHIM_SYSCALL(getpriority, 2, shim_do_getpriority, int, int, which, int, who)

DEFINE_SHIM_SYSCALL(sched_setparam, 2, shim_do_sched_setparam, int, pid_t, pid,
                    struct __kernel_sched_param*, param)

DEFINE_SHIM_SYSCALL(sched_getparam, 2, shim_do_sched_getparam, int, pid_t, pid,
                    struct __kernel_sched_param*, param)

DEFINE_SHIM_SYSCALL(sched_setscheduler, 3, shim_do_sched_setscheduler, int, pid_t, pid,
                    int, policy, struct __kernel_sched_param*, param)

DEFINE_SHIM_SYSCALL(sched_getscheduler, 1, shim_do_sched_getscheduler, int, pid_t, pid)

DEFINE_SHIM_SYSCALL(sched_get_priority_max, 1, shim_do_sched_get_priority_max, int, int, policy)

DEFINE_SHIM_SYSCALL(sched_get_priority_min, 1, shim_do_sched_get_priority_min, int, int, policy)

DEFINE_SHIM_SYSCALL(sched_rr_get_interval, 2, shim_do_sched_rr_get_interval, int, pid_t, pid,
                    struct timespec*, interval)

SHIM_SYSCALL_PASSTHROUGH(mlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(munlock, 2, int, void*, start, size_t, len)

SHIM_SYSCALL_PASSTHROUGH(mlockall, 1, int, int, flags)

SHIM_SYSCALL_PASSTHROUGH(munlockall, 0, int)

SHIM_SYSCALL_PASSTHROUGH(vhangup, 0, int)

SHIM_SYSCALL_PASSTHROUGH(modify_ldt, 3, int, int, func, void*, ptr, unsigned long, bytecount)

SHIM_SYSCALL_PASSTHROUGH(pivot_root, 2, int, const char*, new_root, const char*, put_old)

SHIM_SYSCALL_PASSTHROUGH(_sysctl, 1, int, struct __kernel_sysctl_args*, args)

SHIM_SYSCALL_PASSTHROUGH(prctl, 5, int, int, option, unsigned long, arg2, unsigned long, arg3,
                         unsigned long, arg4, unsigned long, arg5)

DEFINE_SHIM_SYSCALL(arch_prctl, 2, shim_do_arch_prctl, void*, int, code, void*, addr)

void* shim_do_arch_prctl(int code, void* addr) {
    if (code != ARCH_SET_FS && code != ARCH_GET_FS) {
        debug("Not supported flag (0x%x) passed to arch_prctl\n", code);
        return (void*)-ENOSYS;
    }

    switch (code) {
        case ARCH_SET_FS:
            if (!addr)
                return (void*)-EINVAL;

            update_fs_base((unsigned long)addr);
            debug("set fs_base to 0x%lx\n", (unsigned long)addr);
            return NULL;

        case ARCH_GET_FS:
            return (void*)DkSegmentRegister(PAL_SEGMENT_FS, NULL) ?: (void*)-PAL_ERRNO;
    }

    return (void*)-ENOSYS;
}

SHIM_SYSCALL_PASSTHROUGH(adjtimex, 1, int, struct ____kernel_timex*, txc_p)

/* setrlimit: sys/shim_getrlimit.c */
DEFINE_SHIM_SYSCALL(setrlimit, 2, shim_do_setrlimit, int, int, resource, struct __kernel_rlimit*,
                    rlim)

/* chroot: sys/shim_isolate.c */
DEFINE_SHIM_SYSCALL(chroot, 1, shim_do_chroot, int, const char*, filename)

SHIM_SYSCALL_PASSTHROUGH(sync, 0, int)

SHIM_SYSCALL_PASSTHROUGH(acct, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(settimeofday, 2, int, struct timeval*, tv, struct __kernel_timezone*, tz)

SHIM_SYSCALL_PASSTHROUGH(mount, 5, int, char*, dev_name, char*, dir_name, char*, type,
                         unsigned long, flags, void*, data)

SHIM_SYSCALL_PASSTHROUGH(umount2, 2, int, const char*, target, int, flags)

SHIM_SYSCALL_PASSTHROUGH(swapon, 2, int, const char*, specialfile, int, swap_flags)

SHIM_SYSCALL_PASSTHROUGH(swapoff, 1, int, const char*, specialfile)

SHIM_SYSCALL_PASSTHROUGH(reboot, 4, int, int, magic1, int, magic2, int, cmd, void*, arg)

SHIM_SYSCALL_PASSTHROUGH(sethostname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHROUGH(setdomainname, 2, int, char*, name, int, len)

SHIM_SYSCALL_PASSTHROUGH(iopl, 1, int, int, level)

SHIM_SYSCALL_PASSTHROUGH(ioperm, 3, int, unsigned long, from, unsigned long, num, int, on)

SHIM_SYSCALL_PASSTHROUGH(create_module, 2, int, const char*, name, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(init_module, 3, int, void*, umod, unsigned long, len, const char*, uargs)

SHIM_SYSCALL_PASSTHROUGH(delete_module, 2, int, const char*, name_user, unsigned int, flags)

/*
SHIM_SYSCALL_PASSTHROUGH (get_kernel_syms, 1, int, struct kernel_sym *, table)
*/

SHIM_SYSCALL_PASSTHROUGH(query_module, 5, int, const char*, name, int, which, void*, buf, size_t,
                         bufsize, size_t*, retsize)

SHIM_SYSCALL_PASSTHROUGH(quotactl, 4, int, int, cmd, const char*, special, qid_t, id, void*, addr)

/*
SHIM_SYSCALL_PASSTHROUGH (nfsservctl, 3, int, int, cmd, struct nfsctl_arg *,
                          arg, void *, res)
*/

/* shim_getpmsg MISSING
   TODO: getpmsg syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* shim_putpmsg MISSING
   TODO: putpmsg syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* shim_afs_syscall MISSING
   TODO: afs_syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* shim_tuxcall MISSING
   TODO: tuxcall syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* shim_security MISSING
   TODO: security syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* gettid: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(gettid, 0, shim_do_gettid, pid_t)

SHIM_SYSCALL_PASSTHROUGH(readahead, 3, int, int, fd, loff_t, offset, size_t, count)

SHIM_SYSCALL_PASSTHROUGH(setxattr, 5, int, const char*, path, const char*, name, const void*, value,
                         size_t, size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(lsetxattr, 5, int, const char*, path, const char*, name, const void*,
                         value, size_t, size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(fsetxattr, 5, int, int, fd, const char*, name, const void*, value, size_t,
                         size, int, flags)

SHIM_SYSCALL_PASSTHROUGH(getxattr, 4, int, const char*, path, const char*, name, void*, value,
                         size_t, size)

SHIM_SYSCALL_PASSTHROUGH(lgetxattr, 4, int, const char*, path, const char*, name, void*, value,
                         size_t, size)

SHIM_SYSCALL_PASSTHROUGH(fgetxattr, 4, int, int, fd, const char*, name, void*, value, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(listxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(llistxattr, 3, int, const char*, path, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(flistxattr, 3, int, int, fd, char*, list, size_t, size)

SHIM_SYSCALL_PASSTHROUGH(removexattr, 2, int, const char*, path, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(lremovexattr, 2, int, const char*, path, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(fremovexattr, 2, int, int, fd, const char*, name)

DEFINE_SHIM_SYSCALL(tkill, 2, shim_do_tkill, int, pid_t, pid, int, sig)

DEFINE_SHIM_SYSCALL(time, 1, shim_do_time, time_t, time_t*, tloc)

/* futex: sys/shim_futex.c */
DEFINE_SHIM_SYSCALL(futex, 6, shim_do_futex, int, int*, uaddr, int, op, int, val, void*, utime,
                    int*, uaddr2, int, val3)

DEFINE_SHIM_SYSCALL(sched_setaffinity, 3, shim_do_sched_setaffinity, int, pid_t, pid, size_t, len,
                    __kernel_cpu_set_t*, user_mask_ptr)

DEFINE_SHIM_SYSCALL(sched_getaffinity, 3, shim_do_sched_getaffinity, int, pid_t, pid, size_t, len,
                    __kernel_cpu_set_t*, user_mask_ptr)

SHIM_SYSCALL_PASSTHROUGH(set_thread_area, 1, int, struct user_desc*, u_info)

/* no glibc wrapper */

SHIM_SYSCALL_PASSTHROUGH(io_setup, 2, int, unsigned, nr_reqs, aio_context_t*, ctx)

SHIM_SYSCALL_PASSTHROUGH(io_destroy, 1, int, aio_context_t, ctx)

SHIM_SYSCALL_PASSTHROUGH(io_getevents, 5, int, aio_context_t, ctx_id, long, min_nr, long, nr,
                         struct io_event*, events, struct timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(io_submit, 3, int, aio_context_t, ctx_id, long, nr, struct iocb**, iocbpp)

SHIM_SYSCALL_PASSTHROUGH(io_cancel, 3, int, aio_context_t, ctx_id, struct iocb*, iocb,
                         struct io_event*, result)

SHIM_SYSCALL_PASSTHROUGH(get_thread_area, 1, int, struct user_desc*, u_info)

SHIM_SYSCALL_PASSTHROUGH(lookup_dcookie, 3, int, unsigned long, cookie64, char*, buf, size_t, len)

DEFINE_SHIM_SYSCALL(epoll_create, 1, shim_do_epoll_create, int, int, size)

/* shim_epoll_ctl_old MISSING
   TODO: epoll_ctl_old syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

/* shim_epoll_wait_old MISSING
   TODO: epoll_wait_old syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

SHIM_SYSCALL_PASSTHROUGH(remap_file_pages, 5, int, void*, start, size_t, size, int, prot, ssize_t,
                         pgoff, int, flags)

/* getdents64: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(getdents64, 3, shim_do_getdents64, size_t, int, fd, struct linux_dirent64*, buf,
                    size_t, count)

/* set_tid_address: sys/shim_getpid.c */
DEFINE_SHIM_SYSCALL(set_tid_address, 1, shim_do_set_tid_address, int, int*, tidptr)

SHIM_SYSCALL_PASSTHROUGH(restart_syscall, 0, int)

/* semtimedop: sys/shim_semget.c */
DEFINE_SHIM_SYSCALL(semtimedop, 4, shim_do_semtimedop, int, int, semid, struct sembuf*, sops,
                    unsigned int, nsops, const struct timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(fadvise64, 4, int, int, fd, loff_t, offset, size_t, len, int, advice)

SHIM_SYSCALL_PASSTHROUGH(timer_create, 3, int, clockid_t, which_clock, struct sigevent*,
                         timer_event_spec, timer_t*, created_timer_id)

SHIM_SYSCALL_PASSTHROUGH(timer_settime, 4, int, timer_t, timer_id, int, flags,
                         const struct __kernel_itimerspec*, new_setting,
                         struct __kernel_itimerspec*, old_setting)

SHIM_SYSCALL_PASSTHROUGH(timer_gettime, 2, int, timer_t, timer_id, struct __kernel_itimerspec*,
                         setting)

SHIM_SYSCALL_PASSTHROUGH(timer_getoverrun, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHROUGH(timer_delete, 1, int, timer_t, timer_id)

SHIM_SYSCALL_PASSTHROUGH(clock_settime, 2, int, clockid_t, which_clock, const struct timespec*, tp)

/* clock_gettime: sys/shim_time.c */
DEFINE_SHIM_SYSCALL(clock_gettime, 2, shim_do_clock_gettime, int, clockid_t, which_clock,
                    struct timespec*, tp)

DEFINE_SHIM_SYSCALL(clock_getres, 2, shim_do_clock_getres, int, clockid_t, which_clock,
                    struct timespec*, tp)

/* clock_nanosleep: sys/shim_sleep.c */
DEFINE_SHIM_SYSCALL(clock_nanosleep, 4, shim_do_clock_nanosleep, int, clockid_t, which_clock, int,
                    flags, const struct __kernel_timespec*, rqtp, struct __kernel_timespec*, rmtp)

/* exit_group: sys/shim_exit.c */
DEFINE_SHIM_SYSCALL(exit_group, 1, shim_do_exit_group, int, int, error_code)

DEFINE_SHIM_SYSCALL(epoll_wait, 4, shim_do_epoll_wait, int, int, epfd, struct __kernel_epoll_event*,
                    events, int, maxevents, int, timeout_ms)

DEFINE_SHIM_SYSCALL(epoll_ctl, 4, shim_do_epoll_ctl, int, int, epfd, int, op, int, fd,
                    struct __kernel_epoll_event*, event)

DEFINE_SHIM_SYSCALL(tgkill, 3, shim_do_tgkill, int, pid_t, tgid, pid_t, pid, int, sig)

SHIM_SYSCALL_PASSTHROUGH(utimes, 2, int, char*, filename, struct timeval*, utimes)

/* shim_vserver MISSING
   TODO: vserver syscall is not implemented (kernel always returns -ENOSYS),
   how should we handle this?*/

DEFINE_SHIM_SYSCALL(mbind, 6, shim_do_mbind, int, void*, start, unsigned long, len, int, mode,
                    unsigned long*, nmask, unsigned long, maxnode, int, flags)

SHIM_SYSCALL_PASSTHROUGH(set_mempolicy, 3, int, int, mode, unsigned long*, nmask, unsigned long,
                         maxnode)

SHIM_SYSCALL_PASSTHROUGH(get_mempolicy, 5, int, int*, policy, unsigned long*, nmask, unsigned long,
                         maxnode, unsigned long, addr, unsigned long, flags)

SHIM_SYSCALL_PASSTHROUGH(mq_open, 4, int, const char*, name, int, oflag, mode_t, mode,
                         struct __kernel_mq_attr*, attr)

SHIM_SYSCALL_PASSTHROUGH(mq_unlink, 1, int, const char*, name)

SHIM_SYSCALL_PASSTHROUGH(mq_timedsend, 5, int, __kernel_mqd_t, mqdes, const char*, msg_ptr, size_t,
                         msg_len, unsigned int, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHROUGH(mq_timedreceive, 5, int, __kernel_mqd_t, mqdes, char*, msg_ptr, size_t,
                         msg_len, unsigned int*, msg_prio, const struct timespec*, abs_timeout)

SHIM_SYSCALL_PASSTHROUGH(mq_notify, 2, int, __kernel_mqd_t, mqdes, const struct sigevent*,
                         notification)

SHIM_SYSCALL_PASSTHROUGH(mq_getsetattr, 3, int, __kernel_mqd_t, mqdes,
                         const struct __kernel_mq_attr*, mqstat, struct __kernel_mq_attr*, omqstat)

/*
SHIM_SYSCALL_PASSTHROUGH (kexec_load, 4, int, unsigned long, entry,
                          unsigned long, nr_segments, struct kexec_segment *,
                          segments, unsigned long, flags)
*/

SHIM_SYSCALL_PASSTHROUGH(waitid, 5, int, int, which, pid_t, pid, siginfo_t*, infop, int, options,
                         struct __kernel_rusage*, ru)

/*
SHIM_SYSCALL_PASSTHROUGH (add_key, 5, int, const char *, type, const char *,
                          description, const void *, payload, size_t, plen,
                          key_serial_t, destringid)
*/

/*
SHIM_SYSCALL_PASSTHROUGH (request_key, 4, int, const char *, type,
                          const char *, description, const char *, callout_info,
                          key_serial_t, destringid)
*/

/*
SHIM_SYSCALL_PASSTHROUGH (keyctl, 5, int, int, cmd, unsigned long, arg2,
                          unsigned long, arg3, unsigned long, arg4,
                          unsigned long, arg5)
*/

SHIM_SYSCALL_PASSTHROUGH(ioprio_set, 3, int, int, which, int, who, int, ioprio)

SHIM_SYSCALL_PASSTHROUGH(ioprio_get, 2, int, int, which, int, who)

SHIM_SYSCALL_PASSTHROUGH(inotify_init, 0, int)

SHIM_SYSCALL_PASSTHROUGH(inotify_add_watch, 3, int, int, fd, const char*, path, unsigned int, mask)

SHIM_SYSCALL_PASSTHROUGH(inotify_rm_watch, 2, int, int, fd, unsigned int, wd)

SHIM_SYSCALL_PASSTHROUGH(migrate_pages, 4, int, pid_t, pid, unsigned long, maxnode,
                         const unsigned long*, from, const unsigned long*, to)

/* openat: sys/shim_open.c */
DEFINE_SHIM_SYSCALL(openat, 4, shim_do_openat, int, int, dfd, const char*, filename, int, flags,
                    int, mode)

/* mkdirat: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(mkdirat, 3, shim_do_mkdirat, int, int, dfd, const char*, pathname, int, mode)

SHIM_SYSCALL_PASSTHROUGH(mknodat, 4, int, int, dfd, const char*, filename, int, mode, unsigned, dev)

DEFINE_SHIM_SYSCALL(fchownat, 5, shim_do_fchownat, int, int, dfd, const char*, filename, uid_t,
                    user, gid_t, group, int, flag)

SHIM_SYSCALL_PASSTHROUGH(futimesat, 3, int, int, dfd, const char*, filename, struct timeval*,
                         utimes)

/* fstatat: sys/shim_stat.c */
DEFINE_SHIM_SYSCALL(newfstatat, 4, shim_do_newfstatat, int, int, dfd, const char*, filename,
                    struct stat*, statbuf, int, flag)

/* unlinkat: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(unlinkat, 3, shim_do_unlinkat, int, int, dfd, const char*, pathname, int, flag)

/* renameat: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(renameat, 4, shim_do_renameat, int, int, olddfd, const char*, oldname, int,
                    newdfd, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(linkat, 5, int, int, olddfd, const char*, oldname, int, newdfd,
                         const char*, newname, int, flags)

SHIM_SYSCALL_PASSTHROUGH(symlinkat, 3, int, const char*, oldname, int, newdfd, const char*, newname)

SHIM_SYSCALL_PASSTHROUGH(readlinkat, 4, int, int, dfd, const char*, path, char*, buf, int, bufsiz)

/* fchmodat: sys/shim_fs.c */
DEFINE_SHIM_SYSCALL(fchmodat, 3, shim_do_fchmodat, int, int, dfd, const char*, filename, mode_t,
                    mode)

/* faccessat: sys/shim_access.c */
DEFINE_SHIM_SYSCALL(faccessat, 3, shim_do_faccessat, int, int, dfd, const char*, filename, int,
                    mode)

/* pselect6: sys/shim_poll.c */
DEFINE_SHIM_SYSCALL(pselect6, 6, shim_do_pselect6, int, int, nfds, fd_set*, readfds, fd_set*,
                    writefds, fd_set*, errorfds, const struct __kernel_timespec*, tsp,
                    const __sigset_t*, sigmask)

/* ppoll: sys/shim_poll.c */
DEFINE_SHIM_SYSCALL(ppoll, 5, shim_do_ppoll, int, struct pollfd*, fds, int, nfds, struct timespec*,
                    tsp, const __sigset_t*, sigmask, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(unshare, 1, int, int, unshare_flags)

/* set_robust_list: sys/shim_futex.c */
DEFINE_SHIM_SYSCALL(set_robust_list, 2, shim_do_set_robust_list, int, struct robust_list_head*,
                    head, size_t, len)

/* get_roubust_list: sys/shim_futex.c */
DEFINE_SHIM_SYSCALL(get_robust_list, 3, shim_do_get_robust_list, int, pid_t, pid,
                    struct robust_list_head**, head, size_t*, len)

SHIM_SYSCALL_PASSTHROUGH(splice, 6, int, int, fd_in, loff_t*, off_in, int, fd_out, loff_t*, off_out,
                         size_t, len, int, flags)

SHIM_SYSCALL_PASSTHROUGH(tee, 4, int, int, fdin, int, fdout, size_t, len, unsigned int, flags)

SHIM_SYSCALL_PASSTHROUGH(sync_file_range, 4, int, int, fd, loff_t, offset, loff_t, nbytes, int,
                         flags)

SHIM_SYSCALL_PASSTHROUGH(vmsplice, 4, int, int, fd, const struct iovec*, iov, unsigned long,
                         nr_segs, int, flags)

SHIM_SYSCALL_PASSTHROUGH(move_pages, 6, int, pid_t, pid, unsigned long, nr_pages, void**, pages,
                         const int*, nodes, int*, status, int, flags)

SHIM_SYSCALL_PASSTHROUGH(utimensat, 4, int, int, dfd, const char*, filename, struct timespec*,
                         utimes, int, flags)

DEFINE_SHIM_SYSCALL(epoll_pwait, 6, shim_do_epoll_pwait, int, int, epfd,
                    struct __kernel_epoll_event*, events, int, maxevents, int, timeout_ms,
                    const __sigset_t*, sigmask, size_t, sigsetsize)

SHIM_SYSCALL_PASSTHROUGH(signalfd, 3, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask)

SHIM_SYSCALL_PASSTHROUGH(timerfd_create, 2, int, int, clockid, int, flags)

SHIM_SYSCALL_PASSTHROUGH(fallocate, 4, int, int, fd, int, mode, loff_t, offset, loff_t, len)

SHIM_SYSCALL_PASSTHROUGH(timerfd_settime, 4, int, int, ufd, int, flags,
                         const struct __kernel_itimerspec*, utmr, struct __kernel_itimerspec*, otmr)

SHIM_SYSCALL_PASSTHROUGH(timerfd_gettime, 2, int, int, ufd, struct __kernel_itimerspec*, otmr)

/* accept4: sys/shim_socket.c */
DEFINE_SHIM_SYSCALL(accept4, 4, shim_do_accept4, int, int, sockfd, struct sockaddr*, addr,
                    socklen_t*, addrlen, int, flags)

SHIM_SYSCALL_PASSTHROUGH(signalfd4, 4, int, int, ufd, __sigset_t*, user_mask, size_t, sizemask, int,
                         flags)

DEFINE_SHIM_SYSCALL(eventfd, 1, shim_do_eventfd, int, unsigned int, count)

DEFINE_SHIM_SYSCALL (eventfd2, 2, shim_do_eventfd2, int, unsigned int, count, int, flags)

/* epoll_create1: sys/shim_epoll.c */
DEFINE_SHIM_SYSCALL(epoll_create1, 1, shim_do_epoll_create1, int, int, flags)

/* dup3: sys/shim_dup.c */
DEFINE_SHIM_SYSCALL(dup3, 3, shim_do_dup3, int, int, oldfd, int, newfd, int, flags)

/* pipe2: sys/shim_pipe.c */
DEFINE_SHIM_SYSCALL(pipe2, 2, shim_do_pipe2, int, int*, fildes, int, flags)

SHIM_SYSCALL_PASSTHROUGH(inotify_init1, 1, int, int, flags)

SHIM_SYSCALL_PASSTHROUGH(preadv, 5, int, unsigned long, fd, const struct iovec*, vec, unsigned long,
                         vlen, unsigned long, pos_l, unsigned long, pos_h)

SHIM_SYSCALL_PASSTHROUGH(pwritev, 5, int, unsigned long, fd, const struct iovec*, vec,
                         unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h)

SHIM_SYSCALL_PASSTHROUGH(rt_tgsigqueueinfo, 4, int, pid_t, tgid, pid_t, pid, int, sig, siginfo_t*,
                         uinfo)

SHIM_SYSCALL_PASSTHROUGH(perf_event_open, 5, int, struct perf_event_attr*, attr_uptr, pid_t, pid,
                         int, cpu, int, group_fd, int, flags)

DEFINE_SHIM_SYSCALL(recvmmsg, 5, shim_do_recvmmsg, ssize_t, int, fd, struct mmsghdr*, msg, size_t,
                    vlen, int, flags, struct __kernel_timespec*, timeout)

SHIM_SYSCALL_PASSTHROUGH(fanotify_init, 2, int, int, flags, int, event_f_flags)

SHIM_SYSCALL_PASSTHROUGH(fanotify_mark, 5, int, int, fanotify_fd, int, flags, unsigned long, mask,
                         int, fd, const char*, pathname)

DEFINE_SHIM_SYSCALL(prlimit64, 4, shim_do_prlimit64, int, pid_t, pid, int, resource,
                    const struct __kernel_rlimit64*, new_rlim, struct __kernel_rlimit64*, old_rlim)

SHIM_SYSCALL_PASSTHROUGH(name_to_handle_at, 5, int, int, dfd, const char*, name,
                         struct linux_file_handle*, handle, int*, mnt_id, int, flag)

SHIM_SYSCALL_PASSTHROUGH(open_by_handle_at, 3, int, int, mountdirfd, struct linux_file_handle*,
                         handle, int, flags)

SHIM_SYSCALL_PASSTHROUGH(clock_adjtime, 2, int, clockid_t, which_clock, struct timex*, tx)

SHIM_SYSCALL_PASSTHROUGH(syncfs, 1, int, int, fd)

DEFINE_SHIM_SYSCALL(sendmmsg, 4, shim_do_sendmmsg, ssize_t, int, fd, struct mmsghdr*, msg, size_t,
                    vlen, int, flags)

SHIM_SYSCALL_PASSTHROUGH(setns, 2, int, int, fd, int, nstype)

SHIM_SYSCALL_PASSTHROUGH(getcpu, 3, int, unsigned*, cpu, unsigned*, node, struct getcpu_cache*,
                         cache)

/* libos calls */

DEFINE_SHIM_SYSCALL(msgpersist, 2, shim_do_msgpersist, int, int, msqid, int, cmd)

DEFINE_SHIM_SYSCALL(benchmark_rpc, 4, shim_do_benchmark_rpc, int, pid_t, pid, int, times,
                    const void*, buf, size_t, size)

DEFINE_SHIM_SYSCALL(send_rpc, 3, shim_do_send_rpc, size_t, pid_t, pid, const void*, buf, size_t,
                    size)

DEFINE_SHIM_SYSCALL(recv_rpc, 3, shim_do_recv_rpc, size_t, pid_t*, pid, void*, buf, size_t, size)

DEFINE_SHIM_SYSCALL(checkpoint, 1, shim_do_checkpoint, int, const char*, filename)
