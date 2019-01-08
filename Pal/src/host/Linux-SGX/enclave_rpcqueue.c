#include <assert.h>
#include "rpcqueue.h"

void rpc_spin_lock(struct atomic_int* p) {
    while (atomic_cmpxchg(p, SPIN_UNLOCKED, SPIN_LOCKED)) {
        while (atomic_read(p) == SPIN_LOCKED)
            cpu_relax();
    }
}

/* returns 0 if acquired lock; 1 if timed out (counted as # of iterations) */
int rpc_spin_lock_timeout(struct atomic_int* p, uint64_t iterations) {
    while (atomic_cmpxchg(p, SPIN_UNLOCKED, SPIN_LOCKED)) {
        while (atomic_read(p) == SPIN_LOCKED) {
            if (iterations-- == 0)  return 1;
            cpu_relax();
        }
    }
    return 0;
}

void rpc_spin_unlock(struct atomic_int* p) {
    atomic_set(p, SPIN_UNLOCKED);
}

rpc_request_t* rpc_enqueue(rpc_queue_t* q, rpc_request_t* req) {
    rpc_spin_lock(&q->lock);

    if (q->rear - q->front >= RPC_QUEUE_SIZE) {
        rpc_spin_unlock(&q->lock);
        return NULL;
    }

    assert(q->q[q->rear % RPC_QUEUE_SIZE] == NULL);
    q->q[q->rear % RPC_QUEUE_SIZE] = req;
    q->rear++;

    rpc_spin_unlock(&q->lock);
    return req;
}

rpc_request_t* rpc_dequeue(rpc_queue_t* q) {
    rpc_spin_lock(&q->lock);

    if (q->front == q->rear) {
        rpc_spin_unlock(&q->lock);
        return NULL;
    }

    assert(q->q[q->front % RPC_QUEUE_SIZE] != NULL);
    rpc_request_t* req = q->q[q->front % RPC_QUEUE_SIZE];
    q->q[q->front % RPC_QUEUE_SIZE] = NULL;
    q->front++;

    rpc_spin_unlock(&q->lock);
    return req;
}
