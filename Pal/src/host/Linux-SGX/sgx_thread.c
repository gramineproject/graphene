/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_internal.h"
#include "sgx_internal.h"
#include "pal_security.h"

#include <pthread.h>
#include <linux/futex.h>
#include <asm/signal.h>
#include <asm/prctl.h>

#include "sgx_enclave.h"
#include "debugger/sgx_gdb.h"

__thread struct pal_enclave * current_enclave;
__thread sgx_arch_tcs_t * current_tcs;

struct thread_map {
    unsigned int     tid;
    sgx_arch_tcs_t * tcs;
};

static sgx_arch_tcs_t * enclave_tcs;
static int enclave_thread_num;
static struct thread_map * enclave_thread_map;

void create_tcs_mapper (void * tcs_base, unsigned int thread_num)
{
    enclave_tcs = tcs_base;
    enclave_thread_map = malloc(sizeof(struct thread_map) * thread_num);
    enclave_thread_num = thread_num;

    for (int i = 0 ; i < thread_num ; i++) {
        enclave_thread_map[i].tid = 0;
        enclave_thread_map[i].tcs = &enclave_tcs[i];
    }
}

void map_tcs (unsigned int tid)
{
    for (int i = 0 ; i < enclave_thread_num ; i++)
        if (!enclave_thread_map[i].tid) {
            enclave_thread_map[i].tid = tid;
            current_tcs = enclave_thread_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            break;
        }
}

void unmap_tcs (void)
{
    int index = current_tcs - enclave_tcs;
    struct thread_map * map = &enclave_thread_map[index];
    if (index >= enclave_thread_num)
        return;
    SGX_DBG(DBG_I, "unmap TCS at 0x%08lx\n", map->tcs);
    current_tcs = NULL;
    ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[index] = 0;
    map->tid = 0;
    map->tcs = NULL;
}

static void * thread_start (void * arg)
{
    int tid = INLINE_SYSCALL(gettid, 0);
    map_tcs(tid);
    current_enclave = arg;

    if (!current_tcs) {
        SGX_DBG(DBG_E, "Cannot attach to any TCS!\n");
        return NULL;
    }

    ecall_thread_start();
    unmap_tcs();
    return NULL;
}

int clone_thread (void)
{
    pthread_t thread;
    return pthread_create(&thread, NULL, thread_start, current_enclave);
}

int interrupt_thread (void * tcs)
{
    int index = (sgx_arch_tcs_t *) tcs - enclave_tcs;
    struct thread_map * map = &enclave_thread_map[index];
    if (index >= enclave_thread_num)
        return -PAL_ERROR_INVAL;
    if (!map->tid)
        return -PAL_ERROR_INVAL;
    INLINE_SYSCALL(tgkill, 3, PAL_SEC()->pid, map->tid, SIGCONT);
    return 0;
}
