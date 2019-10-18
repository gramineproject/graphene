#include "assert.h"
#include "pal_internal.h"
#include "sgx_internal.h"
#include "pal_security.h"

#include <linux/futex.h>
#include <linux/signal.h>
#include <asm/errno.h>
#include <asm/signal.h>
#include <asm/prctl.h>

#include "sgx_enclave.h"
#include "debugger/sgx_gdb.h"

struct thread_map {
    unsigned int     tid;
    sgx_arch_tcs_t * tcs;
};

static sgx_arch_tcs_t * enclave_tcs;
static int enclave_thread_num;
static struct thread_map * enclave_thread_map;

static void spin_lock(struct atomic_int* p) {
    while (atomic_cmpxchg(p, 0, 1)) {
        while (atomic_read(p) == 1)
            CPU_RELAX();
    }
}

static void spin_unlock(struct atomic_int* p) {
    atomic_set(p, 0);
}

static struct atomic_int tcs_lock = ATOMIC_INIT(0);

void create_tcs_mapper (void * tcs_base, unsigned int thread_num)
{
    size_t thread_map_size = ALIGN_UP_POW2(sizeof(struct thread_map) * thread_num, PRESET_PAGESIZE);

    enclave_tcs = tcs_base;
    enclave_thread_num = thread_num;
    enclave_thread_map = (struct thread_map*)INLINE_SYSCALL(mmap, 6, NULL, thread_map_size,
                                                            PROT_READ | PROT_WRITE,
                                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (uint32_t i = 0 ; i < thread_num ; i++) {
        enclave_thread_map[i].tid = 0;
        enclave_thread_map[i].tcs = &enclave_tcs[i];
    }
}

void map_tcs(unsigned int tid) {
    spin_lock(&tcs_lock);
    for (int i = 0 ; i < enclave_thread_num ; i++)
        if (!enclave_thread_map[i].tid) {
            enclave_thread_map[i].tid = tid;
            get_tcb_linux()->tcs = enclave_thread_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            break;
        }
    spin_unlock(&tcs_lock);
}

void unmap_tcs(void) {
    int index = get_tcb_linux()->tcs - enclave_tcs;
    struct thread_map * map = &enclave_thread_map[index];

    assert(index < enclave_thread_num);

    spin_lock(&tcs_lock);
    get_tcb_linux()->tcs = NULL;
    ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[index] = 0;
    map->tid = 0;
    spin_unlock(&tcs_lock);
}

/*
 * pal_thread_init(): An initialization wrapper of a newly-created thread (including
 * the first thread). This function accepts a TCB pointer to be set to the GS register
 * of the thread. The rest of the TCB is used as the alternative stack for signal
 * handling. Notice that this sets up the untrusted thread -- an enclave thread is set
 * up by other means (e.g., the GS register is set by an SGX-enforced TCS.OGSBASGX).
 */
int pal_thread_init(void* tcbptr) {
    PAL_TCB_LINUX* tcb = tcbptr;
    int ret;

    /* set GS reg of this thread to thread's TCB; after this point, can use get_tcb_linux() */
    ret = INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, tcb);
    if (IS_ERR(ret)) {
        ret = -EPERM;
        goto out;
    }

    if (tcb->alt_stack) {
        /* align stack to 16 bytes */
        void* alt_stack_top = ALIGN_DOWN_PTR(tcb, 16);
        assert(alt_stack_top > tcb->alt_stack);
        stack_t ss;
        ss.ss_sp    = alt_stack_top;
        ss.ss_flags = 0;
        ss.ss_size  = alt_stack_top - tcb->alt_stack;

        ret = INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
        if (IS_ERR(ret)) {
            ret = -EPERM;
            goto out;
        }
    }

    int tid = INLINE_SYSCALL(gettid, 0);
    map_tcs(tid);  /* updates tcb->tcs */

    if (!tcb->tcs) {
        SGX_DBG(DBG_E,
                "There are no available TCS pages left for a new thread!\n"
                "Please try to increase sgx.thread_num in the manifest.\n"
                "The current value is %d\n", enclave_thread_num);
        ret = -ENOMEM;
        goto out;
    }

    if (!tcb->stack) {
        /* only first thread doesn't have a stack (it uses the one provided by Linux); first
         * thread calls ecall_enclave_start() instead of ecall_thread_start() so just exit */
        return 0;
    }

    /* not-first (child) thread, start it */
    ecall_thread_start();

    unmap_tcs();
    ret = 0;
out:
    INLINE_SYSCALL(munmap, 2, tcb->stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
    return ret;
}

void thread_exit(int status) {
    PAL_TCB_LINUX* tcb = get_tcb_linux();

    /* technically, async signals were already blocked before calling this function
     * (by sgx_ocall_exit()) but we keep it here for future proof */
    block_async_signals(true);

    if (tcb->alt_stack) {
        stack_t ss;
        ss.ss_sp    = NULL;
        ss.ss_flags = SS_DISABLE;
        ss.ss_size  = 0;

        /* take precautions to unset the TCB and alternative stack first */
        INLINE_SYSCALL(arch_prctl, 2, ARCH_SET_GS, 0);
        INLINE_SYSCALL(sigaltstack, 2, &ss, NULL);
    }

    /* free the thread stack */
    INLINE_SYSCALL(munmap, 2, tcb->stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
    /* after this line, needs to exit the thread immediately */

    INLINE_SYSCALL(exit, 1, status);
    while (true) {
        /* nothing */
    }
}

int clone_thread(void) {
    int ret = 0;

    void* stack = (void*)INLINE_SYSCALL(mmap, 6, NULL, THREAD_STACK_SIZE + ALT_STACK_SIZE,
                                        PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_ERR_P(stack))
        return -ENOMEM;

    void* child_stack_top = stack + THREAD_STACK_SIZE;

    /* initialize TCB at the top of the alternative stack */
    PAL_TCB_LINUX* tcb = child_stack_top + ALT_STACK_SIZE - sizeof(PAL_TCB_LINUX);
    tcb->common.self   = &tcb->common;
    tcb->enclave       = get_tcb_linux()->enclave;
    tcb->alt_stack     = child_stack_top;
    tcb->stack         = stack;
    tcb->tcs           = NULL;  /* initialized by child thread */

    /* align child_stack to 16 */
    child_stack_top = ALIGN_DOWN_PTR(child_stack_top, 16);

    int dummy_parent_tid_field = 0;
    ret = clone(pal_thread_init, child_stack_top,
                CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SYSVSEM|
                CLONE_THREAD|CLONE_SIGHAND|CLONE_PTRACE|
                CLONE_PARENT_SETTID,
                (void*) tcb,
                &dummy_parent_tid_field, NULL);

    if (IS_ERR(ret)) {
        INLINE_SYSCALL(munmap, 2, stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
        return -ERRNO(ret);
    }
    return 0;
}

int interrupt_thread (void * tcs)
{
    int index = (sgx_arch_tcs_t *) tcs - enclave_tcs;
    struct thread_map * map = &enclave_thread_map[index];
    if (index >= enclave_thread_num)
        return -EINVAL;
    if (!map->tid)
        return -EINVAL;
    INLINE_SYSCALL(tgkill, 3, get_tcb_linux()->enclave->pal_sec.pid, map->tid, SIGCONT);
    return 0;
}
