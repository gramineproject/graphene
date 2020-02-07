#ifndef _SHIM_THREAD_H_
#define _SHIM_THREAD_H_

#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_tcb.h>
#include <shim_utils.h>
#include <shim_signal.h>
#include <shim_handle.h>
#include <shim_vma.h>

#include <api.h>
#include <pal.h>
#include <list.h>

struct shim_handle;
struct shim_fd_map;
struct shim_dentry;
struct shim_signal_log;

#define WAKE_QUEUE_TAIL ((void*)1)
/* If next is NULL, then this node is not on any queue.
 * Otherwise it is a valid pointer to the next node or WAKE_QUEUE_TAIL. */
struct wake_queue_node {
    struct wake_queue_node* next;
};
struct wake_queue_head {
    struct wake_queue_node* first;
};

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
#ifndef ALIAS_VFORK_AS_FORK
    /* dummy thread: stores blocked parent thread for vfork */
    struct shim_thread * dummy;
#endif
    /* child handles; protected by thread->lock */
    LISTP_TYPE(shim_thread) children;
    /* nodes in child handles; protected by the parent's lock */
    LIST_TYPE(shim_thread) siblings;
    /* nodes in global handles; protected by thread_list_lock */
    LIST_TYPE(shim_thread) list;

    struct shim_handle_map * handle_map;

    /* child tid */
    int* set_child_tid;
    int* clear_child_tid;      /* LibOS zeroes it to notify parent that thread exited */
    int  clear_child_tid_pal;  /* PAL zeroes it to notify LibOS that thread exited */

    /* signal handling */
    __sigset_t signal_mask;
    struct shim_signal_handle signal_handles[NUM_SIGS];
    struct atomic_int has_signal;
    struct shim_signal_log * signal_logs;
    bool suspend_on_signal;
    stack_t signal_altstack;

    /* futex robust list */
    struct robust_list_head* robust_list;

    PAL_HANDLE scheduler_event;

    struct wake_queue_node wake_queue;

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
    shim_tcb_t * shim_tcb;
    void * frameptr;

    REFTYPE ref_count;
    struct shim_lock lock;

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
    struct shim_lock lock;

#ifdef PROFILE
    unsigned long exit_time;
#endif
};

int init_thread (void);

static inline bool is_internal(struct shim_thread *thread)
{
    return thread->tid >= INTERNAL_TID_BASE;
}

void get_thread (struct shim_thread * thread);
void put_thread (struct shim_thread * thread);
void get_simple_thread (struct shim_simple_thread * thread);
void put_simple_thread (struct shim_simple_thread * thread);

void update_fs_base (unsigned long fs_base);

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
struct shim_thread* get_cur_thread (void) {
    return SHIM_TCB_GET(tp);
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
    shim_tcb_t * tcb = shim_get_tcb();
    IDTYPE tid = 0;

    if (thread) {
        if (tcb->tp && tcb->tp != thread)
            put_thread(tcb->tp);

        if (tcb->tp != thread)
            get_thread(thread);

        tcb->tp = thread;
        thread->shim_tcb = tcb;
        tid = thread->tid;

        if (!is_internal(thread) && !thread->signal_logs) {
            thread->signal_logs = signal_logs_alloc();
            assert(thread->signal_logs); /* FIXME on ENOMEM */
        }
    } else if (tcb->tp) {
        put_thread(tcb->tp);
        tcb->tp = NULL;
    } else {
        BUG();
    }

    if (tcb->tid != tid) {
        tcb->tid = tid;
        if (tcb->debug_buf)
            debug_setprefix(tcb);
    }
}

static inline void thread_setwait (struct shim_thread ** queue,
                                   struct shim_thread * thread)
{
    if (!thread)
        thread = get_cur_thread();
    DkEventClear(thread->scheduler_event);
    if (queue) {
        get_thread(thread);
        *queue = thread;
    }
}

static inline int thread_sleep (uint64_t timeout_us)
{
    struct shim_thread * cur_thread = get_cur_thread();

    if (!cur_thread)
        return -EINVAL;

    PAL_HANDLE event = cur_thread->scheduler_event;
    if (!event)
        return -EINVAL;

    if (!DkSynchronizationObjectWait(event, timeout_us))
        return -PAL_ERRNO;

    return 0;
}

static inline void thread_wakeup (struct shim_thread * thread)
{
    DkEventSet(thread->scheduler_event);
}

/* Adds the thread to the wake-up queue.
 * If this thread is already on some queue, then it *will* be woken up soon and there is no need
 * to add it to another queue.
 * queue->first should be a valid pointer or WAKE_QUEUE_TAIL (i.e. cannot be NULL).
 *
 * Returns 0 if the thread was added to the queue, 1 otherwise. */
static inline int add_thread_to_queue(struct wake_queue_head* queue, struct shim_thread* thread) {
    struct wake_queue_node* nptr = NULL;
    struct wake_queue_node* qnode = &thread->wake_queue;

    /* Atomic cmpxchg is enough, no need to take thread->lock */
    if (!__atomic_compare_exchange_n(&qnode->next, &nptr, queue->first,
                                     /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        return 1;
    }

    queue->first = qnode;
    return 0;
}

/* Wakes up all threads on the queue.
 * This is a destructive operation - queue cannot be used after calling this function. */
static inline void wake_queue(struct wake_queue_head* queue) {
    struct wake_queue_node* qnode = queue->first;

    while (qnode != WAKE_QUEUE_TAIL) {
        struct shim_thread* thread = container_of(qnode, struct shim_thread, wake_queue);

        qnode = qnode->next;
        __atomic_store_n(&thread->wake_queue.next, NULL, __ATOMIC_RELAXED);

        thread_wakeup(thread);
        put_thread(thread);
    }
}

extern struct shim_lock thread_list_lock;

/*!
 * \brief Look up the thread for a given id.
 *
 * \param tid Thread id to look for.
 *
 * Searches global threads list for a thread with id equal to \p tid.
 * If no thread was found returns NULL.
 * Increases refcount of the returned thread.
 */
struct shim_thread* lookup_thread(IDTYPE tid);
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

void cleanup_thread(IDTYPE caller, void* thread);
int check_last_thread(struct shim_thread* self);

#ifndef ALIAS_VFORK_AS_FORK
void switch_dummy_thread (struct shim_thread * thread);
#endif

int walk_thread_list (int (*callback) (struct shim_thread *, void *, bool *),
                      void * arg);
int walk_simple_thread_list (int (*callback) (struct shim_simple_thread *,
                                              void *, bool *),
                             void * arg);

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

int thread_exit(struct shim_thread* self, bool send_ipc);
noreturn void thread_or_process_exit(int error_code, int term_signal);

void release_robust_list(struct robust_list_head* head);

/* thread cloning helpers */
struct shim_clone_args {
    PAL_HANDLE create_event;
    PAL_HANDLE initialize_event;
    struct shim_thread * parent, * thread;
    void * stack;
    unsigned long fs_base;
};

void * allocate_stack (size_t size, size_t protect_size, bool user);

static inline __attribute__((always_inline))
bool check_stack_size (struct shim_thread * cur_thread, int size)
{
    if (!cur_thread)
        cur_thread = get_cur_thread();

    void * rsp;
    __asm__ volatile ("movq %%rsp, %0" : "=r"(rsp) :: "memory");

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

int init_stack (const char ** argv, const char ** envp,
                int ** argcpp, const char *** argpp,
                elf_auxv_t ** auxpp);

#endif /* _SHIM_THREAD_H_ */
