/* Copyright (C) 2014 Stony Brook University
   Copyright (C) 2019 Invisible Things Lab
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * "The futexes are also cursed."
 * "But they come in a choice of three flavours!"
 *                                  ~ the Linux kernel source
 */

#include <linux/futex.h>
#include <linux/time.h>
#include <stdint.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "shim_internal.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "spinlock.h"

struct shim_futex;
struct futex_waiter;

DEFINE_LIST(futex_waiter);
DEFINE_LISTP(futex_waiter);
struct futex_waiter {
    struct shim_thread* thread;
    uint32_t bitset;
    LIST_TYPE(futex_waiter) list;
    /* futex field is guarded by futex_list lock, do not use it without taking that lock first.
     * This is needed to ensure that a waiter knows what futex they were sleeping on, after they
     * wake-up (because they could have been requeued to another futex).*/
    struct shim_futex* futex;
};

DEFINE_LIST(shim_futex);
DEFINE_LISTP(shim_futex);
struct shim_futex {
    uint32_t* uaddr;
    LISTP_TYPE(futex_waiter) waiters;
    LIST_TYPE(shim_futex) list;
    /* This lock guards every access to uaddr and waiters (above).
     * Always take futex_list_lock before taking this lock. */
    spinlock_t lock;
    REFTYPE _ref_count;
};

static LISTP_TYPE(shim_futex) futex_list = LISTP_INIT;
static spinlock_t futex_list_lock = INIT_SPINLOCK_UNLOCKED;

static void get_futex(struct shim_futex* futex) {
    REF_INC(futex->_ref_count);
}

static void put_futex(struct shim_futex* futex) {
    if (!REF_DEC(futex->_ref_count)) {
        free(futex);
    }
}

/*
 * Adds `futex` to `futex_list`.
 *
 * Both `futex_list_lock` and `futex->lock` should be held while calling this function.
 */
static void enqueue_futex(struct shim_futex* futex) {
    get_futex(futex);
    LISTP_ADD_TAIL(futex, &futex_list, list);
}

/*
 * If `futex` has no waiters and is on `futex_list`, takes it off that list.
 *
 * Both futex_list_lock and futex->lock should be held while calling this function.
 */
static void maybe_dequeue_futex(struct shim_futex* futex) {
    if (LISTP_EMPTY(&futex->waiters) && !LIST_EMPTY(futex, list)) {
        LISTP_DEL_INIT(futex, &futex_list, list);
        /* We still hold this futex reference (in the caller), so this won't call free. */
        put_futex(futex);
    }
}

/*
 * Adds `waiter` to `futex` waiters list.
 *
 * Increases refcount of current thread by 1 (in thread_setwait)
 * and of `futex` by 1.
 * Both `futex->lock` and `futex_list_lock` needs to be held.
 */
static void add_futex_waiter(struct futex_waiter* waiter,
                             struct shim_futex* futex,
                             uint32_t bitset) {
    thread_setwait(&waiter->thread, NULL);
    INIT_LIST_HEAD(waiter, list);
    waiter->bitset = bitset;
    get_futex(futex);
    waiter->futex = futex;
    LISTP_ADD_TAIL(waiter, &futex->waiters, list);
}

/*
 * The caller inherits 1 thread's refcount, which previously accounted for waiter->thread being on
 * futex->waiters list.
 */
static struct shim_thread* remove_futex_waiter(struct futex_waiter* waiter,
                                               struct shim_futex* futex) {
    LISTP_DEL_INIT(waiter, &futex->waiters, list);
    return waiter->thread;
}

/*
 * Moves waiter from `futex1` to `futex2`.
 */
static void move_futex_waiter(struct futex_waiter* waiter,
                              struct shim_futex* futex1,
                              struct shim_futex* futex2) {
    LISTP_DEL_INIT(waiter, &futex1->waiters, list);
    get_futex(futex2);
    put_futex(waiter->futex);
    waiter->futex = futex2;
    LISTP_ADD_TAIL(waiter, &futex2->waiters, list);
}

/*
 * Creates a new futex.
 * Sets the new futex refcount to 1.
 */
static struct shim_futex* create_new_futex(uint32_t* uaddr) {
    struct shim_futex* futex;

    futex = calloc(1, sizeof(*futex));
    if (!futex) {
        return NULL;
    }

    REF_SET(futex->_ref_count, 1);

    futex->uaddr = uaddr;
    INIT_LISTP(&futex->waiters);
    INIT_LIST_HEAD(futex, list);
    spinlock_init(&futex->lock);

    return futex;
}

/*
 * Finds a futex in futex_list.
 * Must be called with futex_list_lock held.
 * Increases refcount of futex by 1.
 */
static struct shim_futex* find_futex(uint32_t* uaddr) {
    struct shim_futex* futex;

    LISTP_FOR_EACH_ENTRY(futex, &futex_list, list) {
        if (futex->uaddr == uaddr) {
            get_futex(futex);
            return futex;
        }
    }

    return NULL;
}

/* Since we distinguish futexes by their virtual address, we can as well create a total ordering
 * based on it. */
static int cmp_futexes(struct shim_futex* futex1, struct shim_futex* futex2) {
    uintptr_t f1 = (uintptr_t)futex1->uaddr;
    uintptr_t f2 = (uintptr_t)futex2->uaddr;

    if (f1 < f2) {
        return -1;
    } else if (f1 == f2) {
        return 0;
    } else {
        return 1;
    }
}

/*
 * Locks two futexes in a specifis order.
 * If a futex is NULL, it is just skipped.
 */
static void lock_two_futexes(struct shim_futex* futex1, struct shim_futex* futex2) {
    if (!futex1 && !futex2) {
        return;
    } else if (futex1 && !futex2){
        spinlock_lock(&futex1->lock);
    } else if (!futex1 && futex2) {
        spinlock_lock(&futex2->lock);
    }
    /* Both are not NULL. */

    /* To avoid deadlocks we always take the locks in ascending order of futexes.
     * If both futexes are equal, just take one lock. */
    int cmp = cmp_futexes(futex1, futex2);
    if (cmp < 0) {
        spinlock_lock(&futex1->lock);
        spinlock_lock(&futex2->lock);
    } else if (cmp == 0) {
        spinlock_lock(&futex1->lock);
    } else {
        spinlock_lock(&futex2->lock);
        spinlock_lock(&futex1->lock);
    }
}

static void unlock_two_futexes(struct shim_futex* futex1, struct shim_futex* futex2) {
    if (!futex1 && !futex2) {
        return;
    } else if (futex1 && !futex2){
        spinlock_unlock(&futex1->lock);
    } else if (!futex1 && futex2) {
        spinlock_unlock(&futex2->lock);
    }
    /* Both are not NULL. */

    /* For unlocking order does not matter. */
    int cmp = cmp_futexes(futex1, futex2);
    if (cmp) {
        spinlock_unlock(&futex1->lock);
        spinlock_unlock(&futex2->lock);
    } else {
        spinlock_unlock(&futex1->lock);
    }
}

static uint64_t timespec_to_us(const struct timespec* ts) {
    return ts->tv_sec * 1000000u + ts->tv_nsec / 1000u;
}

static int futex_wait(uint32_t* uaddr, uint32_t val, uint64_t timeout, uint32_t bitset) {
    int ret = 0;
    struct shim_futex* futex = NULL;
    struct shim_thread* thread = NULL;

    spinlock_lock(&futex_list_lock);
    futex = find_futex(uaddr);
    if (!futex) {
        spinlock_unlock(&futex_list_lock);
        futex = create_new_futex(uaddr);
        if (!futex) {
            return -ENOMEM;
        }
        spinlock_lock(&futex_list_lock);
        enqueue_futex(futex);
    }
    spinlock_lock(&futex->lock);

    if (__atomic_load_n(uaddr, __ATOMIC_RELAXED) != val) {
        ret = -EAGAIN;
        goto out;
    }

    struct futex_waiter waiter = { 0 };
    add_futex_waiter(&waiter, futex, bitset);

    spinlock_unlock(&futex->lock);
    spinlock_unlock(&futex_list_lock);

    put_futex(futex);
    /* Just for the sanity; at this point we cannot use this futex reference anymore. */
    futex = NULL;

    ret = thread_sleep(timeout);
    /* On timeout thread_sleep returns -EAGAIN. */
    if (ret == -EAGAIN) {
        ret = -ETIMEDOUT;
    }

    spinlock_lock(&futex_list_lock);
    /* We might have been requeued. Grab the (possibly new) futex reference. */
    futex = waiter.futex;
    assert(futex);
    get_futex(futex);
    spinlock_lock(&futex->lock);

    if (!LIST_EMPTY(&waiter, list)) {
        /* If we woke up due to time out, we were not removed from the waiters list (opposite
         * of when another thread calls FUTEX_WAKE, which would remove us from the list). */
        thread = remove_futex_waiter(&waiter, futex);
    }

    /* At this point we are done using the `waiter` struct and need to give up the futex reference
     * it was holding. */
    put_futex(waiter.futex);

out:
    maybe_dequeue_futex(futex);
    spinlock_unlock(&futex->lock);
    spinlock_unlock(&futex_list_lock);

    if (thread) {
        put_thread(thread);
    }

    put_futex(futex);
    return ret;
}

/*
 * Moves at most `to_wake` waiters from futex to wake queue;
 * In the Linux kernel the number of waiters to wake has type `int` and we follow that here.
 * Normally `bitset` has to be non-zero, here zero means: do not even check it.
 *
 * Must be called with both futex_list_lock and futex->lock held.
 *
 * Returns number of threads worken.
 */
static int move_to_wake_queue(struct shim_futex* futex, uint32_t bitset, int to_wake,
                              struct wake_queue_head* queue) {
    struct futex_waiter* waiter;
    struct futex_waiter* wtmp;
    struct shim_thread* thread;
    int woken = 0;

    LISTP_FOR_EACH_ENTRY_SAFE(waiter, wtmp, &futex->waiters, list) {
        if (bitset && !(waiter->bitset & bitset)) {
            continue;
        }

        thread = remove_futex_waiter(waiter, futex);
        if (add_thread_to_queue(queue, thread)) {
            put_thread(thread);
        }

        /* If to_wake (3rd argument of futex syscall) is 0, the Linux kernel still wakes up
         * one thread - so we do the same here. */
        if (++woken >= to_wake) {
            break;
        }
    }

    maybe_dequeue_futex(futex);

    return woken;
}

static int futex_wake(uint32_t* uaddr, int to_wake, uint32_t bitset) {
    struct shim_futex* futex;
    struct wake_queue_head queue = { .first = WAKE_QUEUE_TAIL };
    int woken = 0;

    if (!bitset) {
        return -EINVAL;
    }

    spinlock_lock(&futex_list_lock);
    futex = find_futex(uaddr);
    if (!futex) {
        spinlock_unlock(&futex_list_lock);
        return 0;
    }

    spinlock_lock(&futex->lock);

    woken = move_to_wake_queue(futex, bitset, to_wake, &queue);

    spinlock_unlock(&futex->lock);
    spinlock_unlock(&futex_list_lock);

    wake_queue(&queue);

    put_futex(futex);

    return woken;
}

/*
 * Sign-extends 12 bit argument to 32 bits.
 */
static int wakeop_arg_extend(int x) {
    if (x >= 0x800) {
        return 0xfffff000 | x;
    }
    return x;
}

static int futex_wake_op(uint32_t* uaddr1, uint32_t* uaddr2, int to_wake1, int to_wake2, uint32_t val3) {
    struct shim_futex* futex1 = NULL;
    struct shim_futex* futex2 = NULL;
    struct wake_queue_head queue = { .first = WAKE_QUEUE_TAIL };
    int ret = 0;

    spinlock_lock(&futex_list_lock);
    futex1 = find_futex(uaddr1);
    futex2 = find_futex(uaddr2);

    lock_two_futexes(futex1, futex2);

    unsigned int op = (val3 >> 28) & 0x7;
    unsigned int cmp = (val3 >> 24) & 0xf;
    int oparg = wakeop_arg_extend((val3 >> 12) & 0xfff);
    int cmparg = wakeop_arg_extend(val3 & 0xfff);
    int oldval;
    bool cmpval;

    if ((val3 >> 28) & FUTEX_OP_OPARG_SHIFT) {
        if (oparg < 0 || oparg > 31) {
            /* In case of invalid argument to shift the Linux kernel just prints a message
             * and fixes the argument, so we do the same. */
            debug("futex_wake_op: invalid shift agrument: %d\n", oparg);
            oparg &= 0x1f;
        }
        oparg = 1 << oparg;
    }

    switch (op) {
        case FUTEX_OP_SET:
            oldval = __atomic_exchange_n(uaddr2, oparg, __ATOMIC_RELAXED);
            break;
        case FUTEX_OP_ADD:
            oldval = __atomic_fetch_add(uaddr2, oparg, __ATOMIC_RELAXED);
            break;
        case FUTEX_OP_OR:
            oldval = __atomic_fetch_or(uaddr2, oparg, __ATOMIC_RELAXED);
            break;
        case FUTEX_OP_ANDN:
            oldval = __atomic_fetch_nand(uaddr2, oparg, __ATOMIC_RELAXED);
            break;
        case FUTEX_OP_XOR:
            oldval = __atomic_fetch_xor(uaddr2, oparg, __ATOMIC_RELAXED);
            break;
        default:
            ret = -ENOSYS;
            goto out_unlock;
    }

    switch (cmp) {
        case FUTEX_OP_CMP_EQ:
            cmpval = oldval == cmparg;
            break;
        case FUTEX_OP_CMP_NE:
            cmpval = oldval != cmparg;
            break;
        case FUTEX_OP_CMP_LT:
            cmpval = oldval < cmparg;
            break;
        case FUTEX_OP_CMP_LE:
            cmpval = oldval <= cmparg;
            break;
        case FUTEX_OP_CMP_GT:
            cmpval = oldval > cmparg;
            break;
        case FUTEX_OP_CMP_GE:
            cmpval = oldval >= cmparg;
            break;
        default:
            ret = -ENOSYS;
            goto out_unlock;
    }

    if (futex1) {
        ret += move_to_wake_queue(futex1, 0, to_wake1, &queue);
    }
    if (futex2 && cmpval) {
        ret += move_to_wake_queue(futex2, 0, to_wake2, &queue);
    }

out_unlock:
    unlock_two_futexes(futex1, futex2);

    spinlock_unlock(&futex_list_lock);

    if (ret > 0) {
        wake_queue(&queue);
    }

    if (futex1) {
        put_futex(futex1);
    }
    if (futex2) {
        put_futex(futex2);
    }
    return ret;
}

static int futex_requeue(uint32_t* uaddr1, uint32_t* uaddr2, int to_wake, int to_requeue, uint32_t* val) {
    struct shim_futex* futex1 = NULL;
    struct shim_futex* futex2 = NULL;
    struct wake_queue_head queue = { .first = WAKE_QUEUE_TAIL };
    int ret = 0,
        woken = 0,
        moved = 0;
    struct futex_waiter* waiter;
    struct futex_waiter* wtmp;
    struct shim_thread* thread;

    if (to_wake < 0 || to_requeue < 0) {
        return -EINVAL;
    }

    spinlock_lock(&futex_list_lock);
    futex2 = find_futex(uaddr2);
    if (!futex2) {
        spinlock_unlock(&futex_list_lock);
        futex2 = create_new_futex(uaddr2);
        if (!futex2) {
            return -ENOMEM;
        }
        spinlock_lock(&futex_list_lock);
        enqueue_futex(futex2);
    }
    futex1 = find_futex(uaddr1);

    lock_two_futexes(futex1, futex2);

    if (val != NULL) {
        if (__atomic_load_n(uaddr1, __ATOMIC_RELAXED) != *val) {
            ret = -EAGAIN;
            goto out_unlock;
        }
    }

    if (futex1) {
        /* We cannot call move_to_wake_queue here, as this functions wakes at least 1 thread,
         * (even if to_wake is 0) and here we want to wake-up exactly to_wake threads.
         * I guess it's better to be compatible and replicate these weird corner cases. */
        LISTP_FOR_EACH_ENTRY_SAFE(waiter, wtmp, &futex1->waiters, list) {
            if (woken < to_wake) {
                thread = remove_futex_waiter(waiter, futex1);
                if (add_thread_to_queue(&queue, thread)) {
                    put_thread(thread);
                }
                ++woken;
            } else if (moved < to_requeue) {
                move_futex_waiter(waiter, futex1, futex2);
                ++moved;
            } else {
                break;
            }
        }

        maybe_dequeue_futex(futex1);

        ret = woken + moved;
    }

out_unlock:
    /* At this point `futex2` always exists - if it had not, we have created it
     * and now it might be not needed anymore. */
    maybe_dequeue_futex(futex2);

    unlock_two_futexes(futex1, futex2);

    spinlock_unlock(&futex_list_lock);

    if (woken > 0) {
        wake_queue(&queue);
    }

    if (futex1) {
        put_futex(futex1);
    }
    if (futex2) {
        put_futex(futex2);
    }
    return ret;

}

#define FUTEX_CHECK_READ 0
#define FUTEX_CHECK_WRITE 1
static int is_valid_futex_ptr(uint32_t* ptr, int check_write) {
    if (!IS_ALIGNED_PTR(ptr, sizeof(*ptr))) {
        return -EINVAL;
    }
    if (test_user_memory(ptr, sizeof(*ptr), check_write)) {
        return -EFAULT;
    }
    return 0;
}

static int _shim_do_futex(uint32_t* uaddr, int op, uint32_t val, void* utime, uint32_t* uaddr2, uint32_t val3) {
    int cmd = op & FUTEX_CMD_MASK;
    uint64_t timeout = NO_TIMEOUT;
    uint32_t val2;

    if (utime && (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET ||
                  cmd == FUTEX_LOCK_PI || cmd == FUTEX_WAIT_REQUEUE_PI)) {
        if (test_user_memory(utime, sizeof(struct timespec), 0)) {
            return -EFAULT;
        }
        timeout = timespec_to_us((struct timespec*)utime);
        if (cmd != FUTEX_WAIT) {
            /* For FUTEX_WAIT, timeout is interpreted as a relative value, which differs from other
             * futex operations, where timeout is interpreted as an absolute value. */
            uint64_t current_time = DkSystemTimeQuery();
            if (!current_time || timeout < current_time) {
                return -EINVAL;
            }
            timeout -= current_time;
        }
    }

    if (cmd == FUTEX_CMP_REQUEUE || cmd == FUTEX_REQUEUE || cmd == FUTEX_WAKE_OP ||
          cmd == FUTEX_CMP_REQUEUE_PI) {
        val2 = (uint32_t)(unsigned long)utime;
    }

    if (op & FUTEX_CLOCK_REALTIME) {
        if (cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAIT_REQUEUE_PI) {
            return -ENOSYS;
        }
        /* Graphene has only one clock for now. */
        debug("Ignoring FUTEX_CLOCK_REALTIME flag\n");
    }

    if (!(op & FUTEX_PRIVATE_FLAG)) {
        debug("Non-private futexes are not supported, assuming implicit FUTEX_PRIVATE_FLAG\n");
    }

    int ret = 0;

    /* `uadddr` should be valid pointer in all cases. */
    ret = is_valid_futex_ptr(uaddr, FUTEX_CHECK_READ);
    if (ret) {
        return ret;
    }

    switch (cmd) {
        case FUTEX_WAIT:
            val3 = FUTEX_BITSET_MATCH_ANY;
            /* fallthrough */
        case FUTEX_WAIT_BITSET:
            return futex_wait(uaddr, val, timeout, val3);
        case FUTEX_WAKE:
            val3 = FUTEX_BITSET_MATCH_ANY;
            /* fallthrough */
        case FUTEX_WAKE_BITSET:
            return futex_wake(uaddr, val, val3);
        case FUTEX_WAKE_OP:
            ret = is_valid_futex_ptr(uaddr2, FUTEX_CHECK_WRITE);
            if (ret) {
                return ret;
            }
            return futex_wake_op(uaddr, uaddr2, val, val2, val3);
        case FUTEX_REQUEUE:
            ret = is_valid_futex_ptr(uaddr2, FUTEX_CHECK_READ);
            if (ret) {
                return ret;
            }
            return futex_requeue(uaddr, uaddr2, val, val2, NULL);
        case FUTEX_CMP_REQUEUE:
            ret = is_valid_futex_ptr(uaddr2, FUTEX_CHECK_READ);
            if (ret) {
                return ret;
            }
            return futex_requeue(uaddr, uaddr2, val, val2, &val3);
        case FUTEX_LOCK_PI:
        case FUTEX_TRYLOCK_PI:
        case FUTEX_UNLOCK_PI:
        case FUTEX_CMP_REQUEUE_PI:
        case FUTEX_WAIT_REQUEUE_PI:
            debug("PI futexes are not yet supported!\n");
            return -ENOSYS;
        default:
            debug("Invalid futex op: %d\n", cmd);
            return -ENOSYS;
    }
}

int shim_do_futex(int* uaddr, int op, int val, void* utime, int* uaddr2, int val3) {
    _Static_assert(sizeof(int) == 4, "futexes are defined to be 32-bit");
    return _shim_do_futex((uint32_t*)uaddr, op, (uint32_t)val, utime, (uint32_t*)uaddr2, (uint32_t)val3);
}

int shim_do_set_robust_list(struct robust_list_head* head, size_t len) {
    if (len != sizeof(struct robust_list_head)) {
        return -EINVAL;
    }

    get_cur_thread()->robust_list = head;
    return 0;
}

int shim_do_get_robust_list(pid_t pid, struct robust_list_head** head, size_t* len) {
    struct shim_thread* thread;
    int ret = 0;

    if (pid) {
        thread = lookup_thread(pid);
        if (!thread) {
            return -ESRCH;
        }
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    if (test_user_memory(head, sizeof(*head), 1) || test_user_memory(len, sizeof(*len), 1)) {
        ret = -EFAULT;
        goto out;
    }

    *head = thread->robust_list;
    *len = sizeof(**head);

out:
    put_thread(thread);
    return ret;
}

/*
 * Process one robust futex, waking a waiter if present.
 * Returns 0 on success, negative value otherwise.
 */
static bool handle_futex_death(uint32_t* uaddr) {
    uint32_t val;

    if (!IS_ALIGNED_PTR(uaddr, sizeof(*uaddr))) {
        return -EINVAL;
    }
    if (!is_valid_futex_ptr(uaddr, 1)) {
        return -EFAULT;
    }

    /* Loop until we successfully set the futex word or see someone else taking this futex. */
    while (1) {
        val = __atomic_load_n(uaddr, __ATOMIC_RELAXED);

        if ((val & FUTEX_TID_MASK) != get_cur_thread()->tid) {
            /* Someone else is holding this futex. */
            return 0;
        }

        /* Mark the FUTEX_OWNER_DIED bit, clear all tid bits. */
        uint32_t new_val = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;

        if (__atomic_compare_exchange_n(uaddr, &val, new_val,
                                        1, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            /* Successfully set the new value, end the loop. */
            break;
        }
    }

    if (val & FUTEX_WAITERS) {
        /* There are waiters present, wake one of them. */
        futex_wake(uaddr, 1, FUTEX_BITSET_MATCH_ANY);
    }

    return 0;
}

/*
 * Fetches robust list entry from user memory, checking invalid pointers.
 * Returns 0 on success, negative value on error.
 */
static bool fetch_robust_entry(struct robust_list** entry, struct robust_list** head) {
    if (test_user_memory(head, sizeof(*head), 0)) {
        return -EFAULT;
    }

    *entry = *head;
    return 0;
}

static uint32_t* entry_to_futex(struct robust_list* entry, long futex_offset) {
    return (uint32_t*)((char*)entry + futex_offset);
}

/*
 * Release all robust futexes.
 * The list itself is in user provided memory - we need to check each pointer before dereferencing
 * it. If any check fails, we silently return and ignore the rest.
 */
void release_robust_list(struct robust_list_head* head) {
    struct robust_list* entry;
    struct robust_list* pending;
    long futex_offset;
    unsigned long limit = ROBUST_LIST_LIMIT;

    /* `&head->list.next` does not dereference head, hence is safe. */
    if (fetch_robust_entry(&entry, &head->list.next)) {
        return;
    }

    if (test_user_memory(&head->futex_offset, sizeof(head->futex_offset), 0)) {
        return;
    }
    futex_offset = head->futex_offset;

    if (fetch_robust_entry(&pending, &head->list_op_pending)) {
        return;
    }

    /* Last entry (or first, if the list is empty) points to the list head. */
    while (entry != &head->list) {
        struct robust_list* next_entry;

        /* Fetch the next entry before waking the next thread. */
        bool ret = fetch_robust_entry(&next_entry, &entry->next);

        if (entry != pending) {
            if (handle_futex_death(entry_to_futex(entry, futex_offset))) {
                return;
            }
        }

        if (ret) {
            return;
        }

        entry = next_entry;

        /* This mostly guards from circular lists. */
        if (!--limit) {
            break;
        }
    }

    if (pending) {
        if (handle_futex_death(entry_to_futex(pending, futex_offset))) {
            return;
        }
    }
}

/*
 * Sets `clear_child_tid` to 0 and wakes at most one waiter on that futex.
 * Ignore all possible errors just bailing out.
 */
void release_clear_child_id(int* clear_child_tid) {
    if (!IS_ALIGNED_PTR(clear_child_tid, sizeof(*clear_child_tid))) {
        return;
    }
    if (test_user_memory(clear_child_tid, sizeof(*clear_child_tid), 1)) {
        return;
    }

    __atomic_store_n(clear_child_tid, 0, __ATOMIC_RELAXED);

    /* We can skip all arguments validation as `clear_child_tid` is checked above. */
    futex_wake((uint32_t*)clear_child_tid, 1, FUTEX_BITSET_MATCH_ANY);
}
