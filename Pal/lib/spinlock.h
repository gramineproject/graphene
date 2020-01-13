#ifndef _SPINLOCK_H
#define _SPINLOCK_H

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

/* Use this to initialize spinlocks with *static* storage duration.
 * According to C standard, there only guarantee we have is that this initialization will happen
 * before main, which by itself is not enough (such store might not be visible before fist lock
 * acquire). Fortunately on gcc global zeroed variables will just end up in .bss - zeroed memory
 * mapped during process creation, hence we are fine.
 *
 * Rest of the struct is zeroed implicitly, hence no need for ifdef here. */
#define INIT_SPINLOCK_UNLOCKED { .lock = 0 }

#ifdef DEBUG_SPINLOCKS_SHIM
static inline void debug_spinlock_take_ownership(spinlock_t* lock) {
    __atomic_store_n(&lock->owner, shim_do_gettid(), __ATOMIC_RELAXED);
}

static inline void debug_spinlock_giveup_ownership(spinlock_t* lock) {
    __atomic_store_n(&lock->owner, 0, __ATOMIC_RELAXED);
}
#else
static inline void debug_spinlock_take_ownership(spinlock_t* lock) {
    (void)lock;
}

static inline void debug_spinlock_giveup_ownership(spinlock_t* lock) {
    (void)lock;
}
#endif // DEBUG_SPINLOCKS_SHIM


/* Use this to initialize spinlocks with *dynamic* storage duration. */
static inline void spinlock_init(spinlock_t *lock) {
    debug_spinlock_giveup_ownership(lock);
    __atomic_store_n(&lock->lock, 0, __ATOMIC_RELAXED);
}

/* Returns 0 if taking the lock succeded, 1 if it was already taken */
static inline int spinlock_trylock(spinlock_t* lock) {
    if (__atomic_exchange_n(&lock->lock, 1, __ATOMIC_ACQUIRE) == 0) {
        debug_spinlock_take_ownership(lock);
        return 0;
    }
    return 1;
}

static inline void spinlock_lock(spinlock_t* lock) {
    int val;

    /* First check if lock is already free. */
    if (__atomic_exchange_n(&lock->lock, 1, __ATOMIC_ACQUIRE) == 0) {
        goto out;
    }

    do {
        /* This check imposes no inter-thread ordering, thus does not slow other threads. */
        while (__atomic_load_n(&lock->lock, __ATOMIC_RELAXED) != 0) {
            __asm__ volatile ("pause");
        }
        /* Seen lock as free, check if it still is, this time with acquire semantics (but only
         * if we really take it). */
        val = 0;
    } while (!__atomic_compare_exchange_n(&lock->lock, &val, 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

out:
    debug_spinlock_take_ownership(lock);
}

static inline void spinlock_unlock(spinlock_t* lock) {
    debug_spinlock_giveup_ownership(lock);
    __atomic_store_n(&lock->lock, 0, __ATOMIC_RELEASE);
}

#ifdef DEBUG_SPINLOCKS
static inline bool _spinlock_is_locked(spinlock_t* lock) {
    return __atomic_load_n(&lock->lock, __ATOMIC_SEQ_CST) != 0;
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
