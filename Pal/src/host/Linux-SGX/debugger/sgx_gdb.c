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
#include <assert.h>
#include <wait.h>
#include <signal.h>

#include "sgx_gdb.h"
#include "../sgx_arch.h"

//#define DEBUG_GDB_PTRACE    1

#if DEBUG_GDB_PTRACE == 1
#define DEBUG(fmt, ...)   do { fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#else
#define DEBUG(fmt, ...)   do {} while (0)
#endif

static
long int host_ptrace (enum __ptrace_request request, pid_t pid,
                      void * addr, void * data)
{
    long int res, ret;

    if (request > 0 && request < 4)
        data = &res;

    ret = syscall((long int) SYS_ptrace,
                  (long int) request,
                  (long int) pid,
                  (long int) addr,
                  (long int) data);

    if (ret < 0) {
        if (request >= 0x4000)
            DEBUG("ptrace(0x%x, %d, %p, %p) = err %d\n", request, pid, addr,
                  data, errno);
        else
            DEBUG("ptrace(%d, %d, %p, %p) = err %d\n", request, pid, addr,
                  data, errno);
    } else {
        if (request >= 0x4000)
            DEBUG("ptrace(0x%x, %d, %p, %p) = 0x%lx\n", request, pid, addr,
                  data, ret);
        else
            DEBUG("ptrace(%d, %d, %p, %p) = 0x%lx\n", request, pid, addr,
                  data, ret);
    }

    if (ret >= 0 && request > 0 && request < 4)
        ret = res;

    return ret;
}

static inline
int host_peektids (int memdev, struct enclave_dbginfo * ei)
{
    long int res;
    void * addr = (void *) DBGINFO_ADDR +
            offsetof(struct enclave_dbginfo, thread_tids);
    void * data = (void *) ei +
            offsetof(struct enclave_dbginfo, thread_tids);

    errno = 0;

    for (int off = 0 ; off < sizeof(ei->thread_tids) ;
         off += sizeof(long int)) {

        res = host_ptrace(PTRACE_PEEKDATA, ei->pid, addr + off, NULL);

        if (errno) {
            DEBUG("Failed getting thread information\n");
            return -1;
        }

        *(long int *) (data + off) = res;
    }

    return 0;
}

static inline
int host_peekonetid (pid_t pid, int memdev, struct enclave_dbginfo * ei)
{
    int ret = host_peektids(memdev, ei);
    if (ret < 0)
        return ret;

    for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
        if (ei->thread_tids[i] == pid)
            return 0;

    DEBUG("No such thread: %d\n", pid);
    return -ESRCH;
}

static
void * get_gpr_addr (int memdev, pid_t pid, struct enclave_dbginfo * ei)
{
    void * tcs_addr = NULL;
    struct { uint64_t ossa; uint32_t cssa, nssa; } tcs_part;
    int ret;

    for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
        if (ei->thread_tids[i] == pid) {
            tcs_addr = ei->tcs_addrs[i];
            break;
        }

    if (!tcs_addr) {
        DEBUG("No such thread: %d\n", pid);
        errno = -ESRCH;
        return NULL;
    }

    ret = pread(memdev, &tcs_part, sizeof(tcs_part),
                (off_t) tcs_addr + offsetof(sgx_arch_tcs_t, ossa));
    if (ret < sizeof(tcs_part)) {
        DEBUG("Can't read TCS data (%p)\n", tcs_addr);
        if (ret >= 0)
            errno = -EFAULT;
        return NULL;
    }

    DEBUG("%d: TCS at 0x%lx\n", pid, (uint64_t) tcs_addr);
    DEBUG("%d: TCS.ossa = 0x%lx TCS.cssa = %d\n", pid, tcs_part.ossa, tcs_part.cssa);
    assert(tcs_part.cssa > 0);

    return (void *) ei->base + tcs_part.ossa + ei->ssaframesize * tcs_part.cssa
                    - sizeof(sgx_arch_gpr_t);
}

static
int host_peekgpr (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                  sgx_arch_gpr_t * gpr)
{
    void * gpr_addr = get_gpr_addr(memdev, pid, ei);
    int ret;

    if (!gpr_addr)
        return -1;

    ret = pread(memdev, gpr, sizeof(sgx_arch_gpr_t), (off_t) gpr_addr);
    if (ret < sizeof(sgx_arch_gpr_t)) {
        DEBUG("Can't read GPR data (%p)\n", gpr_addr);
        if (ret >= 0) {
            errno = -EFAULT;
            ret = -1;
        }
        return ret;
    }

    DEBUG("%d: peek GPR RIP 0x%08lx RBP 0x%08lx\n", pid, gpr->rip, gpr->rbp);
    return 0;
}

static
int host_pokegpr (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                  const sgx_arch_gpr_t * gpr)
{
    void * gpr_addr = get_gpr_addr(memdev, pid, ei);
    int ret;

    if (!gpr_addr)
        return -1;

    DEBUG("%d: poke GPR RIP 0x%08lx RBP 0x%08lx\n", pid, gpr->rip, gpr->rbp);

    assert(gpr->rip > ei->base && gpr->rip < ei->base + ei->size);
    assert(gpr->rsp > ei->base && gpr->rsp < ei->base + ei->size);

    ret = pwrite(memdev, gpr, sizeof(sgx_arch_gpr_t), (off_t) gpr_addr);
    if (ret < sizeof(sgx_arch_gpr_t)) {
        DEBUG("Can't write GPR data (%p)\n", (void *) gpr_addr);
        if (ret >= 0) {
            errno = -EFAULT;
            ret = -1;
        }
        return ret;
    }

    return 0;
}

static inline
void fill_regs (struct user_regs_struct * regs, const sgx_arch_gpr_t * gpr)
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

static inline
void fill_gpr (sgx_arch_gpr_t * gpr, const struct user_regs_struct * regs)
{
    gpr->r15 = regs->r15;
    gpr->r14 = regs->r14;
    gpr->r13 = regs->r13;
    gpr->r12 = regs->r12;
    gpr->rbp = regs->rbp;
    gpr->rbx = regs->rbx;
    gpr->r11 = regs->r11;
    gpr->r10 = regs->r10;
    gpr->r9  = regs->r9;
    gpr->r8  = regs->r8;
    gpr->rax = regs->rax;
    gpr->rcx = regs->rcx;
    gpr->rdx = regs->rdx;
    gpr->rsi = regs->rsi;
    gpr->rdi = regs->rdi;
    //gpr->rax = regs->orig_rax;
    gpr->rip = regs->rip;
    gpr->rflags = regs->eflags;
    gpr->rsp = regs->rsp;
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
int host_pokeuser (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                   const struct user * ud)
{
    sgx_arch_gpr_t gpr;
    int ret;

    ret = host_peekgpr(memdev, pid, ei, &gpr);
    if (ret < 0)
        return ret;

    fill_gpr(&gpr, &ud->regs);

    return host_pokegpr(memdev, pid, ei, &gpr);
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
int host_pokeregs (int memdev, pid_t pid, struct enclave_dbginfo * ei,
                   const struct user_regs_struct * regdata)
{
    sgx_arch_gpr_t gpr;
    int ret;

    ret = host_peekgpr(memdev, pid, ei, &gpr);
    if (ret < 0)
        return ret;

    fill_gpr(&gpr, regdata);

    return host_pokegpr(memdev, pid, ei, &gpr);
}

static struct {
    struct enclave_dbginfo ei;
    pid_t   pid;
    int     memdev;
} memdevs[32];

static int nmemdevs = 0;

int open_memdevice (pid_t pid, int * memdev, struct enclave_dbginfo ** ei)
{
    for (int i = 0 ; i < nmemdevs ; i++)
        if (memdevs[i].pid == pid) {
            *memdev = memdevs[i].memdev;
            *ei = &memdevs[i].ei;
            return 0;
        }

    if (nmemdevs == sizeof(memdevs) / sizeof(memdevs[0]))
        return -ENOMEM;

    struct enclave_dbginfo eib;
    long int res;
    for (int off = 0 ; off < sizeof(eib) ; off += sizeof(long int)) {

        res = host_ptrace(PTRACE_PEEKDATA, pid,
                          (void *) DBGINFO_ADDR + off, NULL);

        if (errno) {
            DEBUG("Failed getting debug information\n");
            return -1;
        }

        *(long int *) ((void *) &eib + off) = res;
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

    /* setting debug bit in TCS flags */
    for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
        if (eib.tcs_addrs[i]) {
            void * addr = eib.tcs_addrs[i] + offsetof(sgx_arch_tcs_t, flags);
            uint64_t flags;
            int ret;

            ret = pread(fd, &flags, sizeof(flags), (off_t) addr);
            if (ret < sizeof(flags)) {
                errno = -EFAULT;
                return -1;
            }

            if (flags & TCS_FLAGS_DBGOPTIN) continue;
            flags |= TCS_FLAGS_DBGOPTIN;

            DEBUG("set TCS debug flag at %p (%lx)\n", addr, flags);

            ret = pwrite(fd, &flags, sizeof(flags), (off_t) addr);
            if (ret < sizeof(flags)) {
                errno = -EFAULT;
                return -1;
            }
        }

    eib.thread_stepping = 0;
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
    struct user_regs_struct regs;
    int ret = host_ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    if (ret < 0) {
        DEBUG("Failed getting registers: PID %d\n", pid);
        return ret;
    }

    DEBUG("%d: User RIP 0x%08llx%s\n", pid, regs.rip,
          ((void *) regs.rip == ei->aep) ? " (in enclave)" : "");

    return ((void *) regs.rip == ei->aep) ? 1 : 0;
}

long int ptrace (enum __ptrace_request request, ...)
{
    long int ret = 0, res;
    va_list ap;
    pid_t pid;
    void * addr, * data;
    int memdev;
    struct enclave_dbginfo * ei;
    int prev_errno = errno;

    va_start(ap, request);
    pid = va_arg(ap, pid_t);
    addr = va_arg(ap, void *);
    data = va_arg(ap, void *);
    va_end(ap);

    ret = open_memdevice(pid, &memdev, &ei);
    if (ret < 0)
        goto do_host_ptrace;

    switch (request) {
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA: {
            DEBUG("%d: PEEKTEXT/PEEKDATA(%d, %p)\n", getpid(), pid, addr);

            if (addr < (void *) ei->base ||
                addr >= (void *) (ei->base + ei->size)) {
                ret = host_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
                break;
            }

            ret = pread(memdev, &res, sizeof(long int), (unsigned long) addr);
            if (ret >= 0)
                ret = res;
            break;
        }

        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA: {
            DEBUG("%d: POKETEXT/POKEDATA(%d, %p, 0x%016lx)\n", getpid(), pid,
                  addr, (long int) data);

            if (addr < (void *) ei->base ||
                addr >= (void *) (ei->base + ei->size)) {
                errno = 0;
                ret = host_ptrace(PTRACE_POKEDATA, pid, addr, data);
                break;
            }

            ret = pwrite(memdev, &data, sizeof(long int), (off_t) addr);
            break;
        }

        case PTRACE_PEEKUSER: {
            struct user userdata;

            if ((off_t) addr >= sizeof(struct user)) {
                ret = -EINVAL;
                break;
            }

            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_ptrace;

            ret = host_peekisinenclave(pid, ei);
            assert(ret >= 0);
            if (!ret)
                goto do_host_ptrace;

            DEBUG("%d: PEEKUSER(%d, %ld)\n", getpid(), pid, (off_t) addr);

            if ((off_t) addr >= sizeof(struct user_regs_struct)) {
                errno = 0;
                ret = host_ptrace(PTRACE_PEEKUSER, pid, addr, NULL);
                break;
            }

            ret = host_peekuser(memdev, pid, ei, &userdata);
            if (ret < 0)
                break;

            ret = *(long int *)((void *) &userdata + (off_t) addr);
            break;
        }

        case PTRACE_POKEUSER: {
            struct user userdata;

            if ((off_t) addr >= sizeof(struct user)) {
                ret = -EINVAL;
                break;
            }

            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_ptrace;

            ret = host_peekisinenclave(pid, ei);
            assert(ret >= 0);
            if (!ret)
                goto do_host_ptrace;

            DEBUG("%d: POKEUSER(%d, %lx)\n", getpid(), pid, (off_t) addr);

            if ((off_t) addr >= sizeof(struct user_regs_struct)) {
                ret = host_ptrace(PTRACE_POKEUSER, pid, addr, data);
                break;
            }

            ret = host_peekuser(memdev, pid, ei, &userdata);
            if (ret < 0)
                break;

            *(long int *)((void *) &userdata + (off_t) addr) = (long int) data;

            ret = host_pokeuser(memdev, pid, ei, &userdata);
            break;
        }

        case PTRACE_GETREGS: {
            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_ptrace;

            ret = host_peekisinenclave(pid, ei);
            assert(ret >= 0);
            if (!ret)
                goto do_host_ptrace;

            DEBUG("%d: GETREGS(%d, %p)\n", getpid(), pid, data);

            ret = host_peekregs(memdev, pid, ei,
                                (struct user_regs_struct *) data);
            break;
        }

        case PTRACE_SETREGS: {
            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_ptrace;

            ret = host_peekisinenclave(pid, ei);
            assert(ret >= 0);
            if (!ret)
                goto do_host_ptrace;

            DEBUG("%d: SETREGS(%d, %p)\n", getpid(), pid, data);

            ret = host_pokeregs(memdev, pid, ei,
                                (struct user_regs_struct *) data);
            break;
        }

        case PTRACE_SINGLESTEP: {
            if (host_peekonetid(pid, memdev, ei) < 0)
                goto do_host_ptrace;

            ret = host_peekisinenclave(pid, ei);
            assert(ret >= 0);
            if (!ret)
                goto do_host_ptrace;

            for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
                if (ei->thread_tids[i] == pid) {
                    ei->thread_stepping |= 1ULL << i;
                    break;
                }

            DEBUG("%d: SINGLESTEP(%d)\n", getpid(), pid);
            goto do_host_ptrace;
        }

        default:
            if (request >= 0x4000)
                DEBUG("*** bypassed ptrace call: 0x%x ***\n", request);
            else
                DEBUG("*** bypassed ptrace call: %d ***\n", request);

        do_host_ptrace:
            errno = prev_errno;
            ret = host_ptrace(request, pid, addr, data);
            break;
    }

    if ((request > 0 && request < 4) ? errno : (ret < 0)) {
        if (request >= 0x4000)
            DEBUG(">>> ptrace(0x%x, %d, %p, %p) = err %d\n", request, pid, addr,
                  data, errno);
        else
            DEBUG(">>> ptrace(%d, %d, %p, %p) = err %d\n", request, pid, addr,
                  data, errno);
    } else {
        if (request >= 0x4000)
            DEBUG(">>> ptrace(0x%x, %d, %p, %p) = 0x%lx\n", request, pid, addr,
                  data, ret);
        else
            DEBUG(">>> ptrace(%d, %d, %p, %p) = 0x%lx\n", request, pid, addr,
                  data, ret);
    }

    return ret;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    pid_t res;

    DEBUG("%d: waitpid(%d)\n", getpid(), pid);

    res = syscall((long int) SYS_wait4,
                  (long int) pid,
                  (long int) status,
                  (long int) options,
                  (long int) NULL);

    if (res == -1 || !status)
        return res;

    if (WIFSTOPPED(*status) && WSTOPSIG(*status) == SIGTRAP) {
        int memdev;
        struct enclave_dbginfo * ei;
        int ret;
        pid = res;

        ret = open_memdevice(pid, &memdev, &ei);
        if (ret < 0)
            goto out;

        if (host_peekonetid(pid, memdev, ei) < 0)
            goto out;


        for (int i = 0 ; i < MAX_DBG_THREADS ; i++)
            if (ei->thread_tids[i] == pid) {
                if (ei->thread_stepping & (1ULL << i)) {
                    ei->thread_stepping &= ~(1ULL << i);
                    goto out;
                }
                goto cont;
            }

        DEBUG("no this thread: %d\n", pid);
        goto out;
cont:

        /* if the target thread is inside the enclave */
        ret = host_peekisinenclave(pid, ei);
        assert(ret >= 0);
        if (ret) {
            sgx_arch_gpr_t gpr;
            uint8_t code;

            ret = host_peekgpr(memdev, pid, ei, &gpr);
            if (ret < 0)
                goto out;

            ret = pread(memdev, &code, sizeof(code), (off_t) gpr.rip);
            if (ret < 0)
                goto out;

            if (code != 0xcc)
                goto out;

            DEBUG("rip 0x%lx points to a breakpoint\n", gpr.rip);
            gpr.rip++;
            ret = host_pokegpr(memdev, pid, ei, &gpr);
            if (ret < 0)
                 goto out;
        }
    }

out:
    return res;
}
