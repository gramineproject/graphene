#ifndef _SHIM_SIGNAL_H_
#define _SHIM_SIGNAL_H_

#include <stdbool.h>

#include "shim_defs.h"
#include "shim_types.h"

#define __WCOREDUMP_BIT 0x80

void sigaction_make_defaults(struct __kernel_sigaction* sig_action);
void thread_sigaction_reset_on_execve(struct shim_thread* thread);

#define BITS_PER_WORD (8 * sizeof(unsigned long))
/* The standard def of this macro is dumb */
#undef _SIGSET_NWORDS
#define _SIGSET_NWORDS (NUM_SIGS / BITS_PER_WORD)

/* Return a mask that includes the bit for SIG only.  */
#define __sigmask(sig) \
    (((unsigned long int)1) << (((sig) - 1) % (8 * sizeof(unsigned long int))))

/* Return the word index for SIG.  */
#define __sigword(sig) (((sig) - 1) / (8 * sizeof(unsigned long int)))

/* Clear all signals from SET.  */
#define __sigemptyset(set)           \
    (__extension__({                 \
        int __cnt = _SIGSET_NWORDS;  \
        __sigset_t* __set = (set);   \
        while (--__cnt >= 0)         \
            __set->__val[__cnt] = 0; \
        0;                           \
    }))

/* Set all signals in SET.  */
#define __sigfillset(set)               \
    (__extension__({                    \
        int __cnt = _SIGSET_NWORDS;     \
        __sigset_t* __set = (set);      \
        while (--__cnt >= 0)            \
            __set->__val[__cnt] = ~0UL; \
        0;                              \
    }))

#define __sigisemptyset(set)               \
    (__extension__({                       \
        int __cnt = _SIGSET_NWORDS;        \
        const __sigset_t* __set = (set);   \
        int __ret = __set->__val[--__cnt]; \
        while (!__ret && --__cnt >= 0)     \
            __ret = __set->__val[__cnt];   \
        __ret == 0;                        \
    }))

#define __sigandset(dest, left, right)                                             \
    (__extension__({                                                               \
        int __cnt = _SIGSET_NWORDS;                                                \
        __sigset_t* __dest = (dest);                                               \
        const __sigset_t* __left  = (left);                                        \
        const __sigset_t* __right = (right);                                       \
        while (--__cnt >= 0)                                                       \
            __dest->__val[__cnt] = (__left->__val[__cnt] & __right->__val[__cnt]); \
        0;                                                                         \
    }))

#define __sigorset(dest, left, right)                                              \
    (__extension__({                                                               \
        int __cnt = _SIGSET_NWORDS;                                                \
        __sigset_t* __dest = (dest);                                               \
        const __sigset_t* __left  = (left);                                        \
        const __sigset_t* __right = (right);                                       \
        while (--__cnt >= 0)                                                       \
            __dest->__val[__cnt] = (__left->__val[__cnt] | __right->__val[__cnt]); \
        0;                                                                         \
    }))

#define __signotset(dest, left, right)                                              \
    (__extension__({                                                                \
        int __cnt = _SIGSET_NWORDS;                                                 \
        __sigset_t* __dest = (dest);                                                \
        const __sigset_t* __left  = (left);                                         \
        const __sigset_t* __right = (right);                                        \
        while (--__cnt >= 0)                                                        \
            __dest->__val[__cnt] = (__left->__val[__cnt] & ~__right->__val[__cnt]); \
        0;                                                                          \
    }))

#define __SIGSETFN(NAME, BODY, CONST)                            \
    static inline int NAME(CONST __sigset_t* __set, int __sig) { \
        unsigned long int __mask = __sigmask(__sig);             \
        unsigned long int __word = __sigword(__sig);             \
        return BODY;                                             \
    }

__SIGSETFN(shim_sigismember, (__set->__val[__word] & __mask) ? 1 : 0, __const)
__SIGSETFN(shim_sigaddset, ((__set->__val[__word] |= __mask), 0), )
__SIGSETFN(shim_sigdelset, ((__set->__val[__word] &= ~__mask), 0), )

#define __sigismember shim_sigismember
#define __sigaddset   shim_sigaddset
#define __sigdelset   shim_sigdelset

void clear_illegal_signals(__sigset_t* set);

struct shim_signal {
    siginfo_t siginfo;
};

void get_pending_signals(__sigset_t* set);
bool have_pending_signals(void);

/*!
 * \brief Return stack pointer to use in a signal handler.
 *
 * \param sp Current stack pointer value.
 * \param use_altstack True if alternative stack should be used.
 *
 * Returns value to be used as a new stack pointer in the signal handler, depending on the current
 * thread's settings.
 */
uint64_t get_stack_for_sighandler(uint64_t sp, bool use_altstack);
/*!
 * \brief Check whether address is on alternative stack.
 *
 * \param sp Stack pointer value.
 * \param alt_stack Pointer to the alternative stack.
 *
 * Returns `true` if \p sp is on \p alt_stack.
 */
bool is_on_altstack(uint64_t sp, stack_t* alt_stack);

struct shim_thread;

int init_signal(void);

int append_signal(struct shim_thread* thread, siginfo_t* info);

void get_sig_mask(struct shim_thread* thread, __sigset_t* mask);
void set_sig_mask(struct shim_thread* thread, const __sigset_t* new_set);

int kill_current_proc(siginfo_t* info);
int do_kill_thread(IDTYPE sender, IDTYPE tgid, IDTYPE tid, int sig, bool use_ipc);
int do_kill_proc(IDTYPE sender, IDTYPE tgid, int sig, bool use_ipc);
int do_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig);

void fill_siginfo_code_and_status(siginfo_t* info, int signal, int exit_code);

#endif /* _SHIM_SIGNAL_H_ */
