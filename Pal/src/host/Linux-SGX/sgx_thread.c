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

enum {
        TCS_ALLOC = 0,
        TCS_UNALLOC,
};

struct thread_map {
    unsigned int         tid;
    unsigned int         thread_index;
    unsigned int         status;
    sgx_arch_tcs_t *     tcs;
    unsigned long        tcs_addr;
    unsigned long        ssa_addr;
    unsigned long        tls_addr;
    unsigned long	 aux_stack_addr; /* only applicable to EDMM */
    unsigned long        enclave_entry;
};

static sgx_arch_tcs_t * enclave_tcs;
static int enclave_thread_num;
static int enclave_max_thread_num;
static struct thread_map * enclave_thread_map;

/* create_tcs_mapper initializes the thread information for each threads
 * thread_num: the number of threads statically allocated
 * max_thread_num: the maximum number of threads could be allocated under EDMM
 */
void create_tcs_mapper (unsigned long ssa_base, unsigned long tcs_base, unsigned long tls_base, unsigned long aux_stack_base, unsigned long enclave_entry,
                                                unsigned int thread_num, unsigned int max_thread_num)
{
    enclave_tcs = (sgx_arch_tcs_t*)tcs_base;
    enclave_thread_num = thread_num;
    enclave_max_thread_num = max_thread_num;

    enclave_thread_map = malloc(sizeof(struct thread_map) * enclave_max_thread_num);

    for (int i = 0 ; i < enclave_max_thread_num ; i++) {
        enclave_thread_map[i].tid = 0;
        enclave_thread_map[i].thread_index = i;
        enclave_thread_map[i].tcs = NULL;
        enclave_thread_map[i].ssa_addr = ssa_base + i * pagesize * 2;
        enclave_thread_map[i].tcs_addr = tcs_base + i * pagesize;
        enclave_thread_map[i].tls_addr = tls_base + i * pagesize;
	enclave_thread_map[i].aux_stack_addr = aux_stack_base ? aux_stack_base - i * AUX_STACK_SIZE_PER_THREAD: 0;
        enclave_thread_map[i].enclave_entry = enclave_entry;
        enclave_thread_map[i].tcs = &enclave_tcs[i];

        enclave_thread_map[i].status = TCS_UNALLOC;
    }
}

void create_thread_context(struct thread_map * thread_info)
{
    /* using management thread for setup newly-created thread context */
    current_tcs = enclave_thread_map[enclave_thread_num].tcs;
    
    ecall_thread_setup((void*)thread_info);
    
    mktcs(thread_info->tcs_addr);

    ecall_thread_create((void*)thread_info);
}

void map_tcs (unsigned int tid)
{
    for (int i = 0 ; i < enclave_thread_num ; i++){
        if (!enclave_thread_map[i].tid) {
            enclave_thread_map[i].tid = tid;
            current_tcs = enclave_thread_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            return ;
        }
    }

    /* EDMM create thread dynamically after static threads run out 
     * There is one thread at enclave_thead_map[enclave_thread_num]
     * which is dedicated as management thread for creating new threads
     * start to create threads with enclave_thread_map[enclave_thread_num + 1]
     */
    for (int i = enclave_thread_num + 1; i < enclave_max_thread_num; i++){
        if (!enclave_thread_map[i].tid){
		printf("enclave_thread_map[%d].tcs_addr: %p\n", i, enclave_thread_map[i].tcs_addr);
		
                /* Allocate the thread context (SSA/TLS/TCS) for new
                 * thread if not allocated previously */
                if (enclave_thread_map[i].status == TCS_UNALLOC) {
                        // TODO: Potential race in map_tcs? need a mutex here? 
                        create_thread_context(enclave_thread_map + i);
                        enclave_thread_map[i].status = TCS_ALLOC;
                }
                enclave_thread_map[i].tid = tid;
                current_tcs = enclave_thread_map[i].tcs;
            ((struct enclave_dbginfo *) DBGINFO_ADDR)->thread_tids[i] = tid;
            return ;
        }
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
