/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "sgx_gdb.h"
#include "../sgx_arch.h"

//#define DEBUG_GDB_PTRACE    1

#if DEBUG_GDB_PTRACE == 1
#define DEBUG(fmt, ...)   do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#else
#define DEBUG(fmt, ...)   do {} while (0)
#endif

static
long int __host_ptrace (enum __ptrace_request request, va_list * ap)
{
    pid_t pid = va_arg(ap, pid_t);
    void * addr = va_arg(ap, void *);
    void * data = va_arg(ap, void *);
    long int res, ret;

    if (request > 0 && request < 4)
       data = &ret;

    res = syscall((long int) SYS_ptrace,
                  (long int) request,
                  (long int) pid,
                  (long int) addr,
                  (long int) data);

    if (res >= 0 && request > 0 && request < 4) {
        errno = 0;
        res = ret;
    }

    if (request > 0 && request < 4)
       data = NULL;

    if (res < 0) {
        if (request >= 0x4000)
            DEBUG("ptrace(0x%x, %d, %p, %p) = -1 (err=%d)\n", request, pid, addr,
                  data, errno);
        else
            DEBUG("ptrace(%d, %d, %p, %p) = -1 (err=%d)\n", request, pid, addr,
                  data, errno);
    } else {
        if (request >= 0x4000)
            DEBUG("ptrace(0x%x, %d, %p, %p) = 0x%lx\n", request, pid, addr, data, res);
        else
            DEBUG("ptrace(%d, %d, %p, %p) = 0x%lx\n", request, pid, addr, data, res);
    }

    return res;
}

static
long int host_ptrace (enum __ptrace_request request, ...)
{
    va_list ap;
    va_start(ap, request);
    long int ret = __host_ptrace(request, &ap);
    va_end(ap);
    return ret;
}

static
int host_peekdata (pid_t pid, void * addr, void * data, int size)
{
    for (int off = 0 ; off < size ; off += sizeof(long int)) {
        long int ret = host_ptrace(PTRACE_PEEKDATA, pid, addr + off);

        if (ret < 0)
            return ret;

        *(long int *) (data + off) = ret;
    }

    return 0;
}

static
int host_pokedata (pid_t pid, void * addr, void * data, int size)
{
    for (int off = 0 ; off < size ; off += sizeof(long int)) {
        long int ret = host_ptrace(PTRACE_POKEDATA, pid, addr + off,
                                   *(long int *) (data + off));

        if (ret < 0)
            return ret;
    }

    return 0;
}

static inline
int host_peektids (int memdev, struct enclave_dbginfo * ei)
{
    long int ret;
    ret = host_peekdata(ei->pid,
                        (void *) DBGINFO_ADDR +
                        offsetof(struct enclave_dbginfo, thread_tids),
                        ei->thread_tids,
                        sizeof(ei->thread_tids));
    if (ret < 0) {
        DEBUG("Failed getting thread information\n");
        return ret;
    }

    for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
        if (ei->thread_tids[i]) {
            DEBUG("thread %d: GPR at %p\n", ei->thread_tids[i],
                  (void *) ei->thread_gprs[i]);
        }

    return ret;
}

static inline
int host_peekonetid (pid_t pid, int memdev, struct enclave_dbginfo * ei)
{
    int ret = host_peektids(memdev, ei);
    if (ret < 0)
        return ret;

    for (int i = 0 ;
         i < sizeof(ei->thread_tids) / sizeof(ei->thread_tids[0]) ;
         i++)
        if (ei->thread_tids[i] == pid)
            return 0;

    DEBUG("No such thread: %d\n", pid);
    return -ESRCH;
}


static
int host_peekgpr (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                  sgx_arch_gpr_t * gpr)
{
    int ret;
    unsigned long gpr_addr = 0;

    for (int i = 0 ;
         i < sizeof(ei->thread_tids) / sizeof(ei->thread_tids[0]) ;
         i++)
        if (ei->thread_tids[i] == pid) {
            gpr_addr = ei->thread_gprs[i];
            break;
        }

    if (!gpr_addr) {
        DEBUG("No such thread: %d\n", pid);
        errno = -ESRCH;
        return -1;
    }

    ret = pread(memdev, gpr, sizeof(sgx_arch_gpr_t), gpr_addr);
    if (ret < sizeof(sgx_arch_gpr_t)) {
        DEBUG("Can't read GPR data (%p)\n", (void *) gpr_addr);
        if (ret >= 0) {
            errno = -EFAULT;
            ret = -1;
        }
        return ret;
    }

    DEBUG("[%d] RIP 0x%08lx RBP 0x%08lx\n", pid, gpr->rip, gpr->rbp);
    return 0;
}

static inline
void fill_regs (struct user_regs_struct * regs, sgx_arch_gpr_t * gpr)
{
    regs->r15 = gpr->r15;
    regs->r14 = gpr->r14;
    regs->r13 = gpr->r13;
    regs->r12 = gpr->r12;
    regs->rbp = gpr->rbp;
    regs->rbx = gpr->rbx;
    regs->r11 = gpr->r11;
    regs->r10 = gpr->r10;
    regs->r9  = gpr->r9;
    regs->r8  = gpr->r8;
    regs->rax = gpr->rax;
    regs->rcx = gpr->rcx;
    regs->rdx = gpr->rdx;
    regs->rsi = gpr->rsi;
    regs->rdi = gpr->rdi;
    regs->orig_rax = gpr->rax;
    regs->rip = gpr->rip;
    regs->eflags = gpr->rflags;
    regs->rsp = gpr->rsp;
}

static
int host_peekuser (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                   struct user * ud)
{
    sgx_arch_gpr_t gpr;
    int ret;

    ret = host_peekgpr(memdev, pid, ei, &gpr);
    if (ret < 0)
        return ret;

    fill_regs(&ud->regs, &gpr);

    return 0;
}

static
int host_peekregs (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                   struct user_regs_struct * regdata)
{
    sgx_arch_gpr_t gpr;
    int ret;

    ret = host_peekgpr(memdev, pid, ei, &gpr);
    if (ret < 0)
        return ret;

    fill_regs(regdata, &gpr);
    return 0;
}

static
int host_peekfpregs (int memdev,pid_t pid, struct enclave_dbginfo * ei,
                     struct user_fpregs_struct * fpregdata)
{
    sgx_arch_gpr_t gpr;
    int ret;

    ret = host_peekgpr(memdev, pid, ei, &gpr);
    if (ret < 0)
        return ret;

    return 0;
}


static struct { pid_t pid; int memdev; struct enclave_dbginfo ei; } memdevs[32];
static int nmemdevs = 0;

int open_memdevice (pid_t pid, int * memdev, struct enclave_dbginfo ** ei)
{
    int ret;

    for (int i = 0 ; i < nmemdevs ; i++)
        if (memdevs[i].pid == pid) {
            *memdev = memdevs[i].memdev;
            *ei = &memdevs[i].ei;
            return 0;
        }

    if (nmemdevs == sizeof(memdevs) / sizeof(memdevs[0]))
        return -ENOMEM;

    struct enclave_dbginfo eib;
    ret = host_peekdata(pid, (void *) DBGINFO_ADDR, &eib,
                        sizeof(struct enclave_dbginfo));
    if (ret < 0) {
        return ret;
    }

    for (int i = 0 ; i < nmemdevs ; i++)
        if (memdevs[i].pid == eib.pid) {
            *memdev = memdevs[i].memdev;
            *ei = &memdevs[i].ei;
            return 0;
        }

    DEBUG("Retrieved enclave information (PID %d)\n", eib.pid);

    char memdev_path[40];
    int fd;
    snprintf(memdev_path, 40, "/proc/%d/mem", pid);
    fd = open(memdev_path, O_RDWR);
    if (fd < 0)
        return fd;

    memdevs[nmemdevs].pid = pid;
    memdevs[nmemdevs].memdev = fd;
    memdevs[nmemdevs].ei = eib;
    *memdev = fd;
    *ei = &memdevs[nmemdevs].ei;
    nmemdevs++;
    return 0;
}

static inline
int host_peekisinenclave (pid_t pid, struct enclave_dbginfo * ei)
{
    long int ret = host_ptrace(PTRACE_PEEKUSER, pid,
                               offsetof(struct user, regs.rip));
    if (ret < 0) {
        DEBUG("Failed peeking user: PID %d\n", pid);
        return ret;
    }

    DEBUG("[%d] User RIP 0x%08lx\n", pid, ret);
    return (ret == ei->aep) ? 1 : 0;
}

long int ptrace (enum __ptrace_request request, ...)
{
    long int ret = 0, res;
    va_list ap;
    pid_t pid;
    void * addr, * data;
    int memdev;
    struct enclave_dbginfo * ei;

#if 0
    if (request >= 0x4000)
        fprintf(stderr, "ptrace(0x%x)\n", request);
    else
        fprintf(stderr, "ptrace(%d)\n", request);
#endif

    va_start(ap, request);
    switch (request) {
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA: {
            pid = va_arg(ap, pid_t);
            addr = va_arg(ap, void *);

            DEBUG("%d: PEEKTEXT/PEEKDATA(%d, %p)\n", getpid(), pid, addr);

            ret = open_memdevice(pid, &memdev, &ei);
            if (ret < 0) {
do_host_peekdata:
                ret = host_ptrace(PTRACE_PEEKDATA, pid, addr);
                break;
            }

            if (addr < (void *) ei->base ||
                addr >= (void *) (ei->base + ei->size))
                goto do_host_peekdata;

            ret = pread(memdev, &res, sizeof(long int), (unsigned long) addr);
            if (ret >= 0)
                ret = res;
            break;
        }

        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA: {
            pid = va_arg(ap, pid_t);
            addr = va_arg(ap, void *);
            data = va_arg(ap, void *);

            DEBUG("%d: POKETEXT/POKEDATA(%d, %p, 0x%016lx)\n", getpid(), pid,
                  addr, (unsigned long) data);

            ret = open_memdevice(pid, &memdev, &ei);
            if (ret < 0) {
do_host_pokedata:
                errno = 0;
                ret = host_ptrace(PTRACE_POKEDATA, pid, addr, data);
                break;
            }

            if (addr < (void *) ei->base ||
                addr >= (void *) (ei->base + ei->size))
                goto do_host_pokedata;

            ret = pwrite(memdev, &data, sizeof(long int), (unsigned long) addr);
            break;
        }

        case PTRACE_PEEKUSER: {
            struct user userdata;
            pid = va_arg(ap, pid_t);
            addr = va_arg(ap, void *);

            DEBUG("%d: PEEKUSER(%d, %p)\n", getpid(), pid, addr);

            if ((unsigned long) addr >= sizeof(struct user)) {
                ret = -EINVAL;
                break;
            }

            ret = open_memdevice(pid, &memdev, &ei);
            if (ret < 0) {
do_host_peekuser:
                errno = 0;
                ret = host_ptrace(PTRACE_PEEKUSER, pid, addr);
                break;
            }

            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_peekuser;

            if ((unsigned long) addr == offsetof(struct user, regs.fs_base) ||
                (unsigned long) addr == offsetof(struct user, regs.gs_base))
                goto do_host_peekuser;

            if ((unsigned long) addr >= sizeof(struct user_regs_struct))
                goto do_host_peekuser;

            ret = host_peekisinenclave(pid, ei);
            if (ret < 0)
                break;
            if (!ret)
                goto do_host_peekuser;

            ret = host_peekuser(memdev, pid, ei, &userdata);
            if (ret < 0)
                break;

            data = (void *) &userdata + (unsigned long) addr;
            ret = *(long int *) data;
            break;
        }

        case PTRACE_GETREGS: {
            pid = va_arg(ap, pid_t);
            addr = va_arg(ap, void *);
            data = va_arg(ap, void *);

            DEBUG("%d: GETREGS(%d, %p)\n", getpid(), pid, data);

            ret = open_memdevice(pid, &memdev, &ei);
            if (ret < 0) {
do_host_getregs:
                errno = 0;
                ret = host_ptrace(PTRACE_GETREGS, pid, addr, data);
                break;
            }

            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_getregs;

            ret = host_peekisinenclave(pid, ei);
            if (ret < 0)
                break;
            if (!ret)
                goto do_host_getregs;

            ret = host_peekregs(memdev, pid, ei,
                                (struct user_regs_struct *) data);
            break;
        }


        default:
            ret = __host_ptrace(request, &ap);
            break;
    }

#if 0
    if (ret < 0 && errno) {
        if (request >= 0x4000)
            fprintf(stderr, "ptrace(0x%x) = -1 (err=%d)\n", request, errno);
        else
            fprintf(stderr, "ptrace(%d) = -1 (err=%d)\n", request, errno);
    }
#endif

    va_end(ap);
    return ret;
}
