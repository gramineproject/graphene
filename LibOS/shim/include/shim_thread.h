/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_THREAD_H_
#define _SHIM_THREAD_H_

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_tls.h>
#include <shim_utils.h>
#include <shim_signal.h>
#include <shim_handle.h>
#include <shim_vma.h>

#include <pal.h>
#include <list.h>

struct shim_handle;
struct shim_fd_map;
struct shim_dentry;
struct shim_signal_handle;
struct shim_signal_log;

DEFINE_LIST(shim_thread);
DEFINE_LISTP(shim_thread);
struct shim_thread {
    /* thread identifiers */
    IDTYPE vmid;
    IDTYPE pgid, ppid, tgid, tid;
    bool in_vm;
    LEASETYPE tid_lease;

    /* credentials */
    IDTYPE uid, gid, euid, egid;

    /* thread pal handle */
    PAL_HANDLE pal_handle;

    /* parent handle */
    struct shim_thread * parent;
    /* thread leader */
    struct shim_thread * leader;
    /* dummy thread */
    struct shim_thread * dummy;
    /* child handles; protected by thread->lock */
    LISTP_TYPE(shim_thread) children;
    /* nodes in child handles; protected by the parent's lock */
    LIST_TYPE(shim_thread) siblings;
    /* nodes in global handles; protected by thread_list_lock */
    LIST_TYPE(shim_thread) list;

    struct shim_handle_map * handle_map;

    /* child tid */
    int * set_child_tid, * clear_child_tid;

    /* signal handling */
    __sigset_t signal_mask;
    struct shim_signal_handle signal_handles[NUM_SIGS];
    struct atomic_int has_signal;
    struct shim_signal_log * signal_logs;
    bool suspend_on_signal;
    stack_t signal_altstack;

    /* futex robust list */
    void * robust_list;

    PAL_HANDLE scheduler_event;

    PAL_HANDLE exit_event;
    int exit_code;
    int term_signal; // Store the terminating signal, if any; needed for
                     // wait() and friends
    bool is_alive;

    PAL_HANDLE child_exit_event;
    LISTP_TYPE(shim_thread) exited_children;

    /* file system */
    struct shim_dentry * root, * cwd;
    mode_t umask;

    /* executable */
    struct shim_handle * exec;

    void * stack, * stack_top, * stack_red;
    void * tcb;
    bool user_tcb; /* is tcb assigned by user? */
    void * frameptr;

    REFTYPE ref_count;
    LOCKTYPE lock;

#ifdef PROFILE
    unsigned long exit_time;
#endif
};

DEFINE_LIST(shim_simple_thread);
struct shim_simple_thread {
    /* VMID and PIDs */
    IDTYPE vmid;
    IDTYPE pgid, tgid, tid;

    /* exit event and status */
    PAL_HANDLE exit_event;
    int exit_code;
    int term_signal;
    bool is_alive;

    /* nodes in global handles */
    LIST_TYPE(shim_simple_thread) list;

    REFTYPE ref_count;
    LOCKTYPE lock;

#ifdef PROFILE
    unsigned long exit_time;
#endif
};

int init_thread (void);

#define SHIM_THREAD_SELF()                                     \
    ({ struct shim_thread * __self;                            \
        asm ("movq %%fs:%c1,%q0" : "=r" (__self)               \
           : "i" (offsetof(__libc_tcb_t, shim_tcb.tp)));       \
      __self; })

#define SAVE_SHIM_THREAD_SELF(__self)                         \
  ({ asm ("movq %q0,%%fs:%c1" : : "r" (__self),               \
          "i" (offsetof(__libc_tcb_t, shim_tcb.tp)));         \
     __self; })

void get_thread (struct shim_thread * thread);
void put_thread (struct shim_thread * thread);
void get_simple_thread (struct shim_simple_thread * thread);
void put_simple_thread (struct shim_simple_thread * thread);

void allocate_tls (void * tcb_location, bool user, struct shim_thread * thread);
void populate_tls (void * tcb_location, bool user);

void debug_setprefix (shim_tcb_t * tcb);

static inline
__attribute__((always_inline))
void debug_setbuf (shim_tcb_t * tcb, bool on_stack)
{
    if (!debug_handle)
        return;

    tcb->debug_buf = on_stack ? __alloca(sizeof(struct debug_buf)) :
                     malloc(sizeof(struct debug_buf));

    debug_setprefix(tcb);
}

static inline
__attribute__((always_inline))
struct shim_thread * get_cur_thread (void)
{
    return SHIM_THREAD_SELF();
}

static inline
__attribute__((always_inline))
bool cur_thread_is_alive (void)
{
    struct shim_thread * thread = get_cur_thread();
    return thread ? thread->is_alive : false;
}

static inline
__attribute__((always_inline))
void set_cur_thread (struct shim_thread * thread)
{
    shim_tcb_t * tcb = SHIM_GET_TLS();
    IDTYPE tid = 0;

    if (thread) {
        if (tcb->tp && tcb->tp != thread)
            put_thread(tcb->tp);

        if (tcb->tp != thread)
            get_thread(thread);

        tcb->tp = thread;
        thread->tcb = container_of(tcb, __libc_tcb_t, shim_tcb);
        tid = thread->tid;

        if (!IS_INTERNAL(thread) && !thread->signal_logs)
            thread->signal_logs = malloc(sizeof(struct shim_signal_log) *
                                         NUM_SIGS);
    } else if (tcb->tp) {
        put_thread(tcb->tp);
        tcb->tp = NULL;
    } else {
        bug();
    }

    if (tcb->tid != tid) {
        tcb->tid = tid;
        debug_setprefix(tcb);
    }
}

static inline void thread_setwait (struct shim_thread ** queue,
                                   struct shim_thread * thread)
{
    if (!thread)
        thread = get_cur_thread();
    get_thread(thread);
    DkEventClear(thread->scheduler_event);
    if (queue)
        *queue = thread;
}

static inline int thread_sleep (uint64_t timeout_us)
{
    struct shim_thread * cur_thread = get_cur_thread();

    if (!cur_thread)
        return -EINVAL;

    PAL_HANDLE event = cur_thread->scheduler_event;
    if (!event)
        return -EINVAL;

    if ( NULL == DkObjectsWaitAny(1, &event, timeout_us))
        return -PAL_ERRNO;

    return 0;
}

static inline void thread_wakeup (struct shim_thread * thread)
{
    DkEventSet(thread->scheduler_event);
}

extern LOCKTYPE thread_list_lock;

struct shim_thread * __lookup_thread (IDTYPE tid);
struct shim_thread * lookup_thread (IDTYPE tid);
struct shim_simple_thread * __lookup_simple_thread (IDTYPE tid);
struct shim_simple_thread * lookup_simple_thread (IDTYPE tid);

void set_as_child (struct shim_thread * parent, struct shim_thread * child);

/* creating and revoking thread objects */
struct shim_thread * get_new_thread (IDTYPE new_tid);
struct shim_thread * get_new_internal_thread (void);
struct shim_simple_thread * get_new_simple_thread (void);

/* thread list utilities */
void add_thread (struct shim_thread * thread);
void del_thread (struct shim_thread * thread);
void add_simple_thread (struct shim_simple_thread * thread);
void del_simple_thread (struct shim_simple_thread * thread);

int check_last_thread (struct shim_thread * self);
void switch_dummy_thread (struct shim_thread * thread);

int walk_thread_list (int (*callback) (struct shim_thread *, void *, bool *),
                      void * arg, bool may_write);
int walk_simple_thread_list (int (*callback) (struct shim_simple_thread *,
                                              void *, bool *),
                             void * arg, bool may_write);

/* reference counting of handle maps */
void get_handle_map (struct shim_handle_map * map);
void put_handle_map (struct shim_handle_map * map);

/* retriving handle mapping */
static inline __attribute__((always_inline))
struct shim_handle_map * get_cur_handle_map (struct shim_thread * thread)
{
    if (!thread)
        thread = get_cur_thread();

    return thread ? thread->handle_map : NULL;
}

static inline __attribute__((always_inline))
void set_handle_map (struct shim_thread * thread,
                     struct shim_handle_map * map)
{
    get_handle_map(map);

    if (!thread)
        thread = get_cur_thread();

    if (thread->handle_map)
        put_handle_map(thread->handle_map);

    thread->handle_map = map;
}

/* shim exit callback */
int thread_exit (struct shim_thread * self, bool send_ipc);
/* If the process was killed by a signal, pass it in the second
 *  argument, else pass zero */
int try_process_exit (int error_code, int term_signal);

/* thread cloning helpers */
struct clone_args {
    PAL_HANDLE create_event;
    PAL_HANDLE initialize_event;
    struct shim_thread * parent, * thread;
    void * stack;
    void * return_pc;
};

int clone_implementation_wrapper(struct clone_args * arg);

void * allocate_stack (size_t size, size_t protect_size, bool user);
int populate_user_stack (void * stack, size_t stack_size,
                         int nauxv, elf_auxv_t ** auxpp,
                         const char *** argvp, const char *** envpp);

static inline __attribute__((always_inline))
bool check_stack_size (struct shim_thread * cur_thread, int size)
{
    if (!cur_thread)
        cur_thread = get_cur_thread();

    void * rsp;
    asm volatile ("movq %%rsp, %0" : "=r"(rsp) :: "memory");

    if (rsp <= cur_thread->stack_top && rsp > cur_thread->stack)
        return size < rsp - cur_thread->stack;

    return false;
}

static inline __attribute__((always_inline))
bool check_on_stack (struct shim_thread * cur_thread, void * mem)
{
    if (!cur_thread)
        cur_thread = get_cur_thread();

    return (mem <= cur_thread->stack_top && mem > cur_thread->stack);
}

int init_stack (const char ** argv, const char ** envp, const char *** argpp,
                int nauxv, elf_auxv_t ** auxpp);

#endif /* _SHIM_THREAD_H_ */
