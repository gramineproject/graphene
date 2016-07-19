/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_internal.h"
#include "sgx_internal.h"

#include <pthread.h>
#include <linux/futex.h>
#include <asm/prctl.h>

#include "sgx_enclave.h"
#include "debugger/sgx_gdb.h"

__thread struct pal_enclave * current_enclave;
__thread void * current_tcs;
__thread unsigned long debug_register;

unsigned long * get_debug_register (void)
{
    return &debug_register;
}

void print_debug_register (void)
{
    SGX_DBG(DBG_E, "debug = %016x\n", debug_register);
}

struct tcs_map {
    unsigned int     tid;
    sgx_arch_tcs_t * tcs;
};

static struct tcs_map * tcs_map;
static int tcs_num;

void create_tcs_mapper (void * tcs_base, unsigned int thread_num)
{
    sgx_arch_tcs_t * all_tcs = tcs_base;

    tcs_map = malloc(sizeof(struct tcs_map) * thread_num);
    for (int i = 0 ; i < thread_num ; i++) {
        tcs_map[i].tid = 0;
        tcs_map[i].tcs = &all_tcs[i];
    }

    tcs_num = thread_num;
}

void map_tcs (unsigned int tid)
{
    for (int i = 0 ; i < tcs_num ; i++)
        if (!tcs_map[i].tid) {
            tcs_map[i].tid = tid;
            current_tcs = tcs_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            break;
        }
}

void unmap_tcs (void)
{
    for (int i = 0 ; i < tcs_num ; i++)
        if (tcs_map[i].tcs == current_tcs) {
            SGX_DBG(DBG_I, "unmap TCS at 0x%08lx\n", tcs_map[i].tcs);
            tcs_map[i].tid = 0;
            current_tcs = NULL;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = 0;
            break;
        }
}

struct thread_arg {
    struct pal_enclave * enclave;
    pthread_t thread;
    void (*func) (void *, void *);
    void * arg;
    unsigned int * child_tid;
    unsigned int tid;
};

static void * thread_start (void * arg)
{
    struct thread_arg * thread_arg = (struct thread_arg *) arg;
    struct thread_arg local_arg = *thread_arg;
    local_arg.tid = thread_arg->tid = INLINE_SYSCALL(gettid, 0);

    INLINE_SYSCALL(futex, 6, &thread_arg->tid, FUTEX_WAKE, 1, NULL, NULL, 0);

    current_enclave = local_arg.enclave;
    map_tcs(local_arg.tid);
    if (!current_tcs) {
        SGX_DBG(DBG_E, "Cannot attach to any TCS!\n");
        return NULL;
    }

    ecall_thread_start(local_arg.func,
                       local_arg.arg,
                       local_arg.child_tid,
                       local_arg.tid);

    unmap_tcs();
    return NULL;
}

int clone_thread(void (*func) (void *, void *), void * arg,
                 unsigned int * child_tid, unsigned int * tid)
{
    int ret;
    struct thread_arg new_arg;

    new_arg.enclave = current_enclave;
    new_arg.func = func;
    new_arg.arg = arg;
    new_arg.child_tid = child_tid;
    new_arg.tid = 0;

    ret = pthread_create(&new_arg.thread, NULL, thread_start, &new_arg);

    if (ret < 0)
        return ret;

    INLINE_SYSCALL(futex, 6, &new_arg.tid, FUTEX_WAIT, 0, NULL, NULL, 0);

    if (tid)
        *tid = new_arg.tid;

    return ret;
}
