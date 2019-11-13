#include "rpcqueue.h"
#include "spinlock.h"

rpc_request_t* rpc_enqueue(rpc_queue_t* q, rpc_request_t* req) {
    spinlock_lock(&q->lock);

    if (q->rear - q->front >= RPC_QUEUE_SIZE) {
        spinlock_unlock(&q->lock);
        return NULL;
    }

    if (q->q[q->rear % RPC_QUEUE_SIZE]) {
        spinlock_unlock(&q->lock);
        return NULL;
    }

    q->q[q->rear % RPC_QUEUE_SIZE] = req;
    q->rear++;

    spinlock_unlock(&q->lock);
    return req;
}

rpc_request_t* rpc_dequeue(rpc_queue_t* q) {
    spinlock_lock(&q->lock);

    if (q->front == q->rear) {
        spinlock_unlock(&q->lock);
        return NULL;
    }

    if (!q->q[q->front % RPC_QUEUE_SIZE]) {
        spinlock_unlock(&q->lock);
        return NULL;
    }

    rpc_request_t* req = q->q[q->front % RPC_QUEUE_SIZE];
    q->q[q->front % RPC_QUEUE_SIZE] = NULL;
    q->front++;

    spinlock_unlock(&q->lock);
    return req;
}
