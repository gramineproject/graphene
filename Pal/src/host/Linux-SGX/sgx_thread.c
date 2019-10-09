#include "assert.h"
#include "pal_internal.h"
#include "sgx_internal.h"
#include "pal_security.h"

#include <pthread.h>
#include <linux/futex.h>
#include <asm/errno.h>
#include <asm/signal.h>
#include <asm/prctl.h>

#include "sgx_enclave.h"
#include "debugger/sgx_gdb.h"

__thread struct pal_enclave * current_enclave;
__thread sgx_arch_tcs_t * current_tcs;

struct thread_map {
    unsigned int     tid;
    bool             created_by_pthread;
    sgx_arch_tcs_t * tcs;
};

static sgx_arch_tcs_t * enclave_tcs;
static int enclave_thread_num;
static struct thread_map * enclave_thread_map;

pthread_mutex_t tcs_lock = PTHREAD_MUTEX_INITIALIZER;

void create_tcs_mapper (void * tcs_base, unsigned int thread_num)
{
    enclave_tcs = tcs_base;
    enclave_thread_map = malloc(sizeof(struct thread_map) * thread_num);
    enclave_thread_num = thread_num;

    for (uint32_t i = 0 ; i < thread_num ; i++) {
        enclave_thread_map[i].tid = 0;
        enclave_thread_map[i].tcs = &enclave_tcs[i];
    }
}

void map_tcs(unsigned int tid, bool created_by_pthread) {
    pthread_mutex_lock(&tcs_lock);
    for (int i = 0 ; i < enclave_thread_num ; i++)
        if (!enclave_thread_map[i].tid) {
            enclave_thread_map[i].tid = tid;
            enclave_thread_map[i].created_by_pthread = created_by_pthread;
            current_tcs = enclave_thread_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            break;
        }
    pthread_mutex_unlock(&tcs_lock);
}

/* return true if unmapped thread was created with pthread_create(), false otherwise */
bool unmap_tcs(void) {
    int index = current_tcs - enclave_tcs;
    bool ret = false;
    struct thread_map * map = &enclave_thread_map[index];

    assert(index < enclave_thread_num);

    pthread_mutex_lock(&tcs_lock);
    current_tcs = NULL;
    ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[index] = 0;
    map->tid = 0;
    ret = map->created_by_pthread;
    pthread_mutex_unlock(&tcs_lock);

    return ret;
}

static void * thread_start (void * arg)
{
    int tid = INLINE_SYSCALL(gettid, 0);
    map_tcs(tid, /*created_by_pthread=*/true);
    current_enclave = arg;

    if (!current_tcs) {
        SGX_DBG(DBG_E,
                "There are no available TCS pages left for a new thread!\n"
                "Please try to increase sgx.thread_num in the manifest.\n"
                "The current value is %d\n", enclave_thread_num);
        return NULL;
    }

    ecall_thread_start();
    unmap_tcs();
    return NULL;
}

void thread_exit(void* rv) {
    pthread_exit(rv);
}

int clone_thread(void) {
    pthread_t thread;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    return pthread_create(&thread, &attr, thread_start, current_enclave);
}

int interrupt_thread (void * tcs)
{
    int index = (sgx_arch_tcs_t *) tcs - enclave_tcs;
    struct thread_map * map = &enclave_thread_map[index];
    if (index >= enclave_thread_num)
        return -EINVAL;
    if (!map->tid)
        return -EINVAL;
    INLINE_SYSCALL(tgkill, 3, PAL_SEC()->pid, map->tid, SIGCONT);
    return 0;
}
