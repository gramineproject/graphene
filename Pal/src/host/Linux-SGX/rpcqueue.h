/*
 * RPC threads are helper threads that run in untrusted mode alongside
 * enclave threads. RPC threads issue system calls on behalf of enclave
 * threads. This allows "exitless" design when app threads never leave
 * the enclave (except for a few syscalls that have to be synchronous).
 *
 * "Exitless" design alleviates expensive OCALLs/ECALLs. This was first
 * proposed by SCONE (by Arnautov et al at OSDI 2016) and by Eleos
 * (by Orenbach et al at EuroSys 2017).
 *
 * Brief description: user must specify "sgx.rpc_thread_num = 2" in manifest
 * to create two RPC threads. If user specifies "0" or omits this directive,
 * then no RPC threads are created and all syscalls are done synchronously
 * (as in previous versions of Graphene-SGX).
 *
 * All enclave and RPC threads work on a single shared RPC queue (global
 * variable `rpc_queue`). To issue syscall, enclave thread enqueues syscall
 * request in the queue and spins waiting for result. RPC threads spin
 * waiting for syscall requests; when request comes, first lucky RPC thread
 * grabs request, issues syscall to OS, and notifies enclave thread by
 * releasing the `in_progress` lock.
 *
 * RPC queue can have up to RPC_QUEUE_SIZE requests simultaneously. All
 * requests are pre-allocated for performance.
 *
 * In addition to handling usual syscalls, we implement special logic for
 * `gettimeofday` syscall. Since it is so frequent, we introduce fast path:
 * global variable `untrusted_time` is updated by each RPC thread periodically
 * and enclave threads read it using `time_ptr` instead of enqueueing request.
 *
 * Some syscalls must be synchronous, in this case enclave thread exits enclave,
 * performs syscall, and goes back into enclave mode. Examples of such syscalls
 * include futex and exit. Poll is a special case: it is used by Graphene-SGX
 * during init, so we only make it asynchronous after app starts serving
 * network connections.
 *
 * NOTE: number of created RPC threads must match max number of simultaneous
 * enclave threads. If there are more RPC threads, CPU time is wasted. If there
 * are less, some enclave threads may starve, especially if there are many
 * blocking syscalls by other enclave threads.
 *
 * TODO: Currently we use one global lock on RPC queue. Could be optimized.
 *
 * Prototype code was written by Meni Orenbach and adapted to Graphene-SGX
 * by Dmitrii Kuvaiskii.
 */
#ifndef QUEUE_H_
#define QUEUE_H_

#define RPC_QUEUE_SIZE 1024 /* num requests in rpc queue */
#define MAX_RPC_THREADS 64   /* max number of RPC threads */

typedef struct {
    int result;
    int ocall_index;
    void* buffer;
    int volatile in_progress;
} rpc_request_t;

typedef struct {
    unsigned long front, rear;
    rpc_request_t* q[RPC_QUEUE_SIZE]; /* queue of syscall requests */
    int rpc_threads[MAX_RPC_THREADS];  /* RPC threads (thread IDs) */
    volatile int rpc_threads_num;     /* number of RPC threads */
    unsigned long * time_ptr;         /* untrusted gettime result */
    int do_async_poll;                /* asynchronous poll() */
    int in_signal_handler; /* prevents deadlock on queue when handling signals
                            * which do syscalls, e.g., logging via write() */
    int volatile _lock;    /* global lock for enclave and RPC threads */
} rpc_queue_t;

void rpc_spin_lock(int volatile *p);
void rpc_spin_unlock(int volatile *p);
rpc_request_t* rpc_enqueue(rpc_queue_t* q, int ocall_index, void* data);
rpc_request_t* rpc_dequeue(rpc_queue_t* q);

#endif /* QUEUE_H_ */
