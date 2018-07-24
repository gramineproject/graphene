#include <stddef.h>
#include "rpcqueue.h"

void rpc_spin_lock(int volatile *p) {
    while (!__sync_bool_compare_and_swap(p, 0, 1)) {
        while (*p)
            __asm__("pause");
    }
}

void rpc_spin_unlock(int volatile *p) {
    asm volatile (""); // acts as a memory barrier
    *p = 0;
}

rpc_request_t* rpc_enqueue(rpc_queue_t* q, int ocall_index, void* data) {
    rpc_spin_lock(&q->_lock);

    if (q->rear - q->front == RPC_QUEUE_SIZE) {
        rpc_spin_unlock(&q->_lock);
        return NULL;
    }

    rpc_request_t* req = q->q[q->rear % RPC_QUEUE_SIZE];
    req->ocall_index = ocall_index;
    req->buffer      = data;
    req->in_progress = 1;
    q->rear++;

    rpc_spin_unlock(&q->_lock);
    return req;
}

rpc_request_t* rpc_dequeue(rpc_queue_t* q) {
    rpc_spin_lock(&q->_lock);

    if (q->front == q->rear) {
        rpc_spin_unlock(&q->_lock);
        return NULL;
    }
    rpc_request_t* req = q->q[q->front % RPC_QUEUE_SIZE];
    q->front++;

    rpc_spin_unlock(&q->_lock);
    return req;
}
