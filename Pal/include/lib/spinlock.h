#ifndef _SPINLOCK_H
#define _SPINLOCK_H

typedef int spinlock_t;

/* Use this to initialize spinlocks with *static* storage duration.
 * According to C standard, there only guarantee we have is that this initialization will happen
 * before main, which by itself is not enough (such store might not be visible before fist lock
 * acquire). Fortunately on gcc global zeroed variables will just end up in .bss - zeroed memory
 * mapped during process creation, hence we are fine. */
#define INIT_SPINLOCK_UNLOCKED 0

/* Use this to initialize spinlocks with *dynamic* storage duration. */
static inline void spinlock_init(spinlock_t *lock) {
    __atomic_store_n(lock, 0, __ATOMIC_RELAXED);
}

/* Returns 0 if taking the lock succeded, 1 if it was already taken */
static inline int spinlock_trylock(spinlock_t *lock) {
    if (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE) == 0) {
        return 0;
    }
    return 1;
}

static inline void spinlock_lock(spinlock_t *lock) {
    int val;

    /* First check if lock is already free. */
    if (__atomic_exchange_n(lock, 1, __ATOMIC_ACQUIRE) == 0) {
        return;
    }

    do {
        /* This check imposes no inter-thread ordering, thus does not slow other threads. */
        while (__atomic_load_n(lock, __ATOMIC_RELAXED) != 0) {
            __asm__ volatile ("pause");
        }
        /* Seen lock as free, check if it still is, this time with acquire semantics (but only
         * if we really take it). */
        val = 0;
    } while (!__atomic_compare_exchange_n(lock, &val, 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));
}

static inline void spinlock_unlock(spinlock_t *lock) {
    __atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

#endif // _SPINLOCK_H
