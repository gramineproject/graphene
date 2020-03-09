#ifndef _SPINLOCK_H
#define _SPINLOCK_H

#include <api.h>

#ifdef DEBUG
#define DEBUG_SPINLOCKS
#endif // DEBUG

#if defined DEBUG_SPINLOCKS && defined IN_SHIM
#define DEBUG_SPINLOCKS_SHIM
#include <shim_types.h>
pid_t shim_do_gettid(void);
#endif // defined DEBUG_SPINLOCKS && defined IN_SHIM

typedef struct {
    int lock;
#ifdef DEBUG_SPINLOCKS_SHIM
    pid_t owner;
#endif // DEBUG_SPINLOCKS_SHIM
} spinlock_t;

/* The below macros are only needed for our own futex implementation (based on Futexes are Tricky)
 * used in the Exitless mechanism (in the RPC queue synchronization). Note that ordering is
 * important due to atomic-decrement in unlock logic. */
#define SPINLOCK_UNLOCKED            0
#define SPINLOCK_LOCKED              1
#define SPINLOCK_LOCKED_NO_WAITERS   1  /* used for futex implementation */
#define SPINLOCK_LOCKED_WITH_WAITERS 2  /* used for futex implementation */

/* Use this to initialize spinlocks with *static* storage duration.
 * According to C standard, there only guarantee we have is that this initialization will happen
 * before main, which by itself is not enough (such store might not be visible before fist lock
 * acquire). Fortunately on gcc global zeroed variables will just end up in .bss - zeroed memory
 * mapped during process creation, hence we are fine.
 *
 * Rest of the struct is zeroed implicitly, hence no need for ifdef here. */
#define INIT_SPINLOCK_UNLOCKED { .lock = SPINLOCK_UNLOCKED }

#ifdef DEBUG_SPINLOCKS_SHIM
static inline void debug_spinlock_take_ownership(spinlock_t* lock) {
    __atomic_store_n(&lock->owner, shim_do_gettid(), __ATOMIC_RELAXED);
}

static inline void debug_spinlock_giveup_ownership(spinlock_t* lock) {
    __atomic_store_n(&lock->owner, SPINLOCK_UNLOCKED, __ATOMIC_RELAXED);
}
#else
static inline void debug_spinlock_take_ownership(spinlock_t* lock) {
    __UNUSED(lock);
}

static inline void debug_spinlock_giveup_ownership(spinlock_t* lock) {
    __UNUSED(lock);
}
#endif // DEBUG_SPINLOCKS_SHIM


/* Use this to initialize spinlocks with *dynamic* storage duration. */
static inline void spinlock_init(spinlock_t* lock) {
    debug_spinlock_giveup_ownership(lock);
    __atomic_store_n(&lock->lock, SPINLOCK_UNLOCKED, __ATOMIC_RELAXED);
}

/* Returns 0 if taking the lock succeded, 1 if it was already taken */
static inline int spinlock_trylock(spinlock_t* lock) {
    if (__atomic_exchange_n(&lock->lock, SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == SPINLOCK_UNLOCKED) {
        debug_spinlock_take_ownership(lock);
        return 0;
    }
    return 1;
}

static inline void spinlock_lock(spinlock_t* lock) {
    int val;

    /* First check if lock is already free. */
    if (__atomic_exchange_n(&lock->lock, SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == SPINLOCK_UNLOCKED) {
        goto out;
    }

    do {
        /* This check imposes no inter-thread ordering, thus does not slow other threads. */
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != SPINLOCK_UNLOCKED) {
            __asm__ volatile ("pause");
        }
        /* Seen lock as free, check if it still is, this time with acquire semantics (but only
         * if we really take it). */
        val = SPINLOCK_UNLOCKED;
    } while (!__atomic_compare_exchange_n(&lock->lock, &val, SPINLOCK_LOCKED, /*weak=*/1,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

out:
    debug_spinlock_take_ownership(lock);
}

/* Returns 0 if taking the lock succeded; 1 if timed out (counted as number of iterations) */
static inline int spinlock_lock_timeout(spinlock_t* lock, unsigned long iterations) {
    int val;

    /* First check if lock is already free. */
    if (__atomic_exchange_n(&lock->lock, SPINLOCK_LOCKED, __ATOMIC_ACQUIRE) == SPINLOCK_UNLOCKED) {
        goto out_success;
    }

    do {
        /* This check imposes no inter-thread ordering, thus does not slow other threads. */
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != SPINLOCK_UNLOCKED) {
            if (iterations == 0) {
                return 1;
            }
            iterations--;
            __asm__ volatile ("pause");
        }
        /* Seen lock as free, check if it still is, this time with acquire semantics (but only
         * if we really take it). */
        val = SPINLOCK_UNLOCKED;
    } while (!__atomic_compare_exchange_n(&lock->lock, &val, SPINLOCK_LOCKED, /*weak=*/1,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

out_success:
    debug_spinlock_take_ownership(lock);
    return 0;
}

/* Semantics are the same as gcc's atomic_compare_exchange_n(): compares the contents of *lock with
 * the contents of *expected; if equal, writes `desired` into *lock. If unequal, current contents of
 * *lock are written into *expected. If `desired` is written into *lock then true is returned. */
static inline int spinlock_cmpxchg(spinlock_t* lock, int* expected, int desired) {
    static_assert(SAME_TYPE(&lock->lock, expected), "spinlock is not implemented as int*");
    return __atomic_compare_exchange_n(&lock->lock, expected, desired, /*weak=*/0,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline void spinlock_unlock(spinlock_t* lock) {
    debug_spinlock_giveup_ownership(lock);
    __atomic_store_n(&lock->lock, SPINLOCK_UNLOCKED, __ATOMIC_RELEASE);
}

#ifdef DEBUG_SPINLOCKS
static inline bool _spinlock_is_locked(spinlock_t* lock) {
    return __atomic_load_n(&lock->lock, __ATOMIC_SEQ_CST) != SPINLOCK_UNLOCKED;
}

#ifdef DEBUG_SPINLOCKS_SHIM
static inline bool spinlock_is_locked(spinlock_t* lock) {
    if (!_spinlock_is_locked(lock)) {
        return false;
    }
    pid_t owner = __atomic_load_n(&lock->owner, __ATOMIC_RELAXED);
    if (owner != shim_do_gettid()) {
        debug("Unexpected lock ownership: owned by: %d, checked in: %d", owner, shim_do_gettid());
        return false;
    }
    return true;
}
#else
static inline bool spinlock_is_locked(spinlock_t* lock) {
    return _spinlock_is_locked(lock);
}
#endif // DEBUG_SPINLOCKS_SHIM

#endif // DEBUG_SPINLOCKS

#endif // _SPINLOCK_H
