/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include <api.h>
#include <asm/errno.h>
#include <linux/futex.h>
#include <stdalign.h>
#include <stdbool.h>

#include "ecall_types.h"
#include "enclave_ocalls.h"
#include "ocall_types.h"
#include "pal_debug.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "rpc_queue.h"
#include "sgx_attest.h"
#include "spinlock.h"

/* Check against this limit if the buffer to be allocated fits on the untrusted stack; if not,
 * buffer will be allocated on untrusted heap. Conservatively set this limit to 1/4 of the
 * actual stack size. Currently THREAD_STACK_SIZE = 2MB, so this limit is 512KB.
 * Note that the main thread is special in that it is handled by Linux, with the typical stack
 * size of 8MB. Thus, 512KB limit also works well for the main thread. */
#define MAX_UNTRUSTED_STACK_BUF (THREAD_STACK_SIZE / 4)

/* global pointer to a single untrusted queue, all accesses must be protected by g_rpc_queue->lock */
rpc_queue_t* g_rpc_queue;

static long sgx_exitless_ocall(uint64_t code, void* ms) {
    /* perform OCALL with enclave exit if no RPC queue (i.e., no exitless); no need for atomics
     * because this pointer is set only once at enclave initialization */
    if (!g_rpc_queue)
        return sgx_ocall(code, ms);

    /* allocate request in a new stack frame on OCALL stack; note that request's lock is used in
     * futex() and must be aligned to at least 4B */
    void* old_ustack = sgx_prepare_ustack();
    rpc_request_t* req = sgx_alloc_on_ustack_aligned(sizeof(*req), alignof(*req));
    if (!req) {
        sgx_reset_ustack(old_ustack);
        return -ENOMEM;
    }

    req->ocall_index = code;
    req->buffer      = ms;
    spinlock_init(&req->lock);

    /* grab the lock on this request (it is the responsibility of RPC thread to unlock it when
     * done); this always succeeds immediately since enclave thread is currently the only owner
     * of the lock */
    spinlock_lock(&req->lock);

    /* enqueue OCALL request into RPC queue; some RPC thread will dequeue it, issue a syscall
     * and, after syscall is finished, release the request's spinlock */
    bool enqueued = rpc_enqueue(g_rpc_queue, req);
    if (!enqueued) {
        /* no space in queue: all RPC threads are busy with outstanding ocalls; fallback to normal
         * syscall path with enclave exit */
        sgx_reset_ustack(old_ustack);
        return sgx_ocall(code, ms);
    }

    /* wait till request processing is finished; try spinlock first */
    int timedout = spinlock_lock_timeout(&req->lock, RPC_SPINLOCK_TIMEOUT);

    /* at this point:
     * - either RPC thread is done with OCALL and released the request's spinlock,
     *   and our enclave thread grabbed lock but it doesn't matter at this point
     *   (OCALL is done, timedout = 0, no need to wait on futex)
     * - or OCALL is still pending and the request is still blocked on spinlock
     *   (OCALL is not done, timedout != 0, let's wait on futex) */

    if (timedout) {
        /* OCALL takes a lot of time, so fallback to waiting on a futex; at this point we exit
         * enclave to perform syscall; this code is based on Mutex 2 from Futexes are Tricky */
        int c = SPINLOCK_UNLOCKED;

        /* at this point can be a subtle data race: RPC thread is only now done with OCALL and
         * moved lock in UNLOCKED state; in this racey case, lock = UNLOCKED = 0 and we do not
         * wait on futex (note that enclave thread grabbed lock but it doesn't matter) */
        if (!spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_NO_WAITERS)) {
            /* allocate futex args on OCALL stack */
            ms_ocall_futex_t* ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
            if (!ms) {
                sgx_reset_ustack(old_ustack);
                return -ENOMEM;
            }

            ms->ms_futex = &req->lock.lock;
            ms->ms_op = FUTEX_WAIT_PRIVATE;
            ms->ms_timeout_us = -1; /* never time out */

            do {
                /* at this point lock = LOCKED_*; before waiting on futex, need to move lock to
                 * LOCKED_WITH_WAITERS; note that check on cmpxchg of lock = UNLOCKED = 0 is for
                 * the same data race as above */
                if (c == SPINLOCK_LOCKED_WITH_WAITERS || /* shortcut: don't need to move lock state */
                    spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_WITH_WAITERS)) {
                    /* at this point, futex(wait) syscall expects lock to be in LOCKED_WITH_WAITERS
                     * set by enclave thread above; if RPC thread moved it back to UNLOCKED, futex()
                     * immediately returns */
                    ms->ms_val = SPINLOCK_LOCKED_WITH_WAITERS;
                    int ret = sgx_ocall(OCALL_FUTEX, ms);
                    if (ret < 0 && ret != -EAGAIN) {
                        sgx_reset_ustack(old_ustack);
                        return -EPERM;
                    }
                }
                c = SPINLOCK_UNLOCKED;
            } while (!spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_WITH_WAITERS));
            /* while-loop is required for spurious futex wake-ups: our enclave thread must wait
             * until lock moves to UNLOCKED (note that enclave thread grabs lock but it doesn't
             * matter at this point) */
        }
    }

    sgx_reset_ustack(old_ustack);
    return req->result;
}

noreturn void ocall_exit(int exitcode, int is_exitgroup)
{
    ms_ocall_exit_t * ms;

    sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    ms->ms_exitcode     = exitcode;
    ms->ms_is_exitgroup = is_exitgroup;

    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us (this
    //     case should be already catched by enclave_entry.S).
    while (true) {
        sgx_ocall(OCALL_EXIT, ms);
    }
}

int ocall_mmap_untrusted (int fd, uint64_t offset,
                          uint64_t size, unsigned short prot,
                          void ** mem)
{
    int retval = 0;
    ms_ocall_mmap_untrusted_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = sgx_exitless_ocall(OCALL_MMAP_UNTRUSTED, ms);

    if (!retval) {
        if (!sgx_copy_ptr_to_enclave(mem, ms->ms_mem, size)) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_munmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;
    ms_ocall_munmap_untrusted_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    if (!sgx_is_completely_outside_enclave(mem, size)) {
        sgx_reset_ustack(old_ustack);
        return -EINVAL;
    }

    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = sgx_exitless_ocall(OCALL_MUNMAP_UNTRUSTED, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

/*
 * Memorize untrusted memory area to avoid mmap/munmap per each read/write IO. Because this cache
 * is per-thread, we don't worry about concurrency. The cache will be carried over thread
 * exit/creation. On fork/exec emulation, untrusted code does vfork/exec, so the mmapped cache
 * will be released by exec host syscall.
 *
 * In case of AEX and consequent signal handling, current thread may be interrupted in the middle
 * of using the cache. If there are OCALLs during signal handling, they could interfere with the
 * normal-execution use of the cache, so 'in_use' atomic protects against it. OCALLs during signal
 * handling do not use the cache and always explicitly mmap/munmap untrusted memory; 'need_munmap'
 * indicates whether explicit munmap is needed at the end of such OCALL.
 */
static int ocall_mmap_untrusted_cache(uint64_t size, void** mem, bool* need_munmap) {
    *need_munmap = false;
    struct untrusted_area* cache = &get_tcb_trts()->untrusted_area_cache;
    uint64_t in_use = 0;
    if (!__atomic_compare_exchange_n(&cache->in_use, &in_use, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        /* AEX signal handling case: cache is in use, so make explicit mmap/munmap */
        int retval = ocall_mmap_untrusted(-1, 0, size, PROT_READ | PROT_WRITE, mem);
        if (IS_ERR(retval)) {
            return retval;
        }
        *need_munmap = true;
        return 0;
    }

    /* normal execution case: cache was not in use, so use it/allocate new one for reuse */
    if (cache->valid) {
        if (cache->size >= size) {
            *mem = cache->mem;
            return 0;
        }
        int retval = ocall_munmap_untrusted(cache->mem, cache->size);
        if (IS_ERR(retval)) {
            cache->valid = false;
            __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
            return retval;
        }
    }

    int retval = ocall_mmap_untrusted(-1, 0, size, PROT_READ | PROT_WRITE, mem);
    if (IS_ERR(retval)) {
        cache->valid = false;
        __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
    } else {
        cache->valid = true;
        cache->mem = *mem;
        cache->size = size;
    }
    return retval;
}

static void ocall_munmap_untrusted_cache(void* mem, uint64_t size, bool need_munmap) {
    if (need_munmap) {
        ocall_munmap_untrusted(mem, size);
        /* there is not much we can do in case of error */
    } else {
        struct untrusted_area* cache = &get_tcb_trts()->untrusted_area_cache;
        __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
    }
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    ms_ocall_cpuid_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_leaf = leaf;
    ms->ms_subleaf = subleaf;

    retval = sgx_exitless_ocall(OCALL_CPUID, ms);

    if (!retval) {
        values[0] = ms->ms_values[0];
        values[1] = ms->ms_values[1];
        values[2] = ms->ms_values[2];
        values[3] = ms->ms_values[3];
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_open_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_flags = flags;
    ms->ms_mode = mode;
    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);

    if (!ms->ms_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_OPEN, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    ms_ocall_close_t *ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_CLOSE, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

ssize_t ocall_read(int fd, void* buf, size_t count) {
    ssize_t retval = 0;
    void* obuf = NULL;
    ms_ocall_read_t* ms;
    void* ms_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();
    if (count > MAX_UNTRUSTED_STACK_BUF) {
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
        if (IS_ERR(retval)) {
            sgx_reset_ustack(old_ustack);
            return retval;
        }
        ms_buf = obuf;
    } else {
        ms_buf = sgx_alloc_on_ustack(count);
        if (!ms_buf) {
            retval = -EPERM;
            goto out;
        }
    }

    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    ms->ms_buf = ms_buf;

    retval = sgx_exitless_ocall(OCALL_READ, ms);

    if (retval > 0) {
        if (!sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_write(int fd, const void* buf, size_t count) {
    ssize_t retval = 0;
    void* obuf = NULL;
    ms_ocall_write_t* ms;
    const void* ms_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();

    if (sgx_is_completely_outside_enclave(buf, count)) {
        /* buf is in untrusted memory (e.g., allowed file mmaped in untrusted memory) */
        ms_buf = buf;
    } else if (sgx_is_completely_within_enclave(buf, count)) {
        /* typical case of buf inside of enclave memory */
        if (count > MAX_UNTRUSTED_STACK_BUF) {
            /* buf is too big and may overflow untrusted stack, so use untrusted heap */
            retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
            if (IS_ERR(retval)) {
                sgx_reset_ustack(old_ustack);
                return retval;
            }
            memcpy(obuf, buf, count);
            ms_buf = obuf;
        } else {
            ms_buf = sgx_copy_to_ustack(buf, count);
        }
    } else {
        /* buf is partially in/out of enclave memory */
        ms_buf = NULL;
    }
    if (!ms_buf) {
        retval = -EPERM;
        goto out;
    }

    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    ms->ms_buf = ms_buf;

    retval = sgx_exitless_ocall(OCALL_WRITE, ms);

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_pread(int fd, void* buf, size_t count, off_t offset) {
    long retval = 0;
    void* obuf = NULL;
    ms_ocall_pread_t* ms;
    void* ms_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();
    if (count > MAX_UNTRUSTED_STACK_BUF) {
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
        if (IS_ERR(retval)) {
            sgx_reset_ustack(old_ustack);
            return retval;
        }
        ms_buf = obuf;
    } else {
        ms_buf = sgx_alloc_on_ustack(count);
        if (!ms_buf) {
            retval = -EPERM;
            goto out;
        }
    }

    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    ms->ms_offset = offset;
    ms->ms_buf = ms_buf;

    retval = sgx_exitless_ocall(OCALL_PREAD, ms);
    if (retval > 0) {
        if (!sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -EPERM;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_pwrite(int fd, const void* buf, size_t count, off_t offset) {
    long retval = 0;
    void* obuf = NULL;
    ms_ocall_pwrite_t* ms;
    const void* ms_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();

    if (sgx_is_completely_outside_enclave(buf, count)) {
        /* buf is in untrusted memory (e.g., allowed file mmaped in untrusted memory) */
        ms_buf = buf;
    } else if (sgx_is_completely_within_enclave(buf, count)) {
        /* typical case of buf inside of enclave memory */
        if (count > MAX_UNTRUSTED_STACK_BUF) {
            /* buf is too big and may overflow untrusted stack, so use untrusted heap */
            retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
            if (IS_ERR(retval)) {
                sgx_reset_ustack(old_ustack);
                return retval;
            }
            memcpy(obuf, buf, count);
            ms_buf = obuf;
        } else {
            ms_buf = sgx_copy_to_ustack(buf, count);
        }
    } else {
        /* buf is partially in/out of enclave memory */
        ms_buf = NULL;
    }
    if (!ms_buf) {
        retval = -EPERM;
        goto out;
    }

    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    ms->ms_offset = offset;
    ms->ms_buf = ms_buf;

    retval = sgx_exitless_ocall(OCALL_PWRITE, ms);

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    ms_ocall_fstat_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FSTAT, ms);

    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    ms_ocall_fionread_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FIONREAD, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    ms_ocall_fsetnonblock_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = sgx_exitless_ocall(OCALL_FSETNONBLOCK, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    ms_ocall_fchmod_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = sgx_exitless_ocall(OCALL_FCHMOD, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    ms_ocall_fsync_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_exitless_ocall(OCALL_FSYNC, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    ms_ocall_ftruncate_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = sgx_exitless_ocall(OCALL_FTRUNCATE, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_mkdir_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_mode = mode;
    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);

    if (!ms->ms_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_MKDIR, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    ms_ocall_getdents_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_size = size;
    ms->ms_dirp = sgx_alloc_on_ustack_aligned(size, alignof(*dirp));

    if (!ms->ms_dirp) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_GETDENTS, ms);

    if (retval > 0) {
        if (!sgx_copy_to_enclave(dirp, size, ms->ms_dirp, retval)) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_resume_thread (void * tcs)
{
    return sgx_exitless_ocall(OCALL_RESUME_THREAD, tcs);
}

int ocall_clone_thread (void)
{
    void* dummy = NULL;
    return sgx_exitless_ocall(OCALL_CLONE_THREAD, dummy);
}

int ocall_create_process(const char* uri, int nargs, const char** args, int* stream_fd, unsigned int* pid) {
    int retval = 0;
    int ulen = uri ? strlen(uri) + 1 : 0;
    ms_ocall_create_process_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms) + nargs * sizeof(char*), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_uri = uri ? sgx_copy_to_ustack(uri, ulen) : NULL;
    if (uri && !ms->ms_uri) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? sgx_copy_to_ustack(args[i], len) : NULL;

        if (args[i] && !ms->ms_args[i]) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    }

    retval = sgx_exitless_ocall(OCALL_CREATE_PROCESS, ms);

    if (!retval) {
        if (pid)
            *pid = ms->ms_pid;
        if (stream_fd)
            *stream_fd = ms->ms_stream_fd;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_futex(int* futex, int op, int val, int64_t timeout_us) {
    int retval = 0;
    ms_ocall_futex_t * ms;

    if (!sgx_is_completely_outside_enclave(futex, sizeof(int))) {
        return -EINVAL;
    }

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout_us = timeout_us;

    retval = sgx_exitless_ocall(OCALL_FUTEX, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    ms_ocall_socketpair_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = sgx_exitless_ocall(OCALL_SOCKETPAIR, ms);

    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_listen(int domain, int type, int protocol, int ipv6_v6only,
                 struct sockaddr* addr, unsigned int* addrlen, struct sockopt* sockopt) {
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_listen_t* ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_ipv6_v6only = ipv6_v6only;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_LISTEN, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = sgx_copy_to_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_accept (int sockfd, struct sockaddr * addr,
                  unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_accept_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_ACCEPT, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = sgx_copy_to_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_connect(int domain, int type, int protocol, int ipv6_v6only,
                  const struct sockaddr* addr, unsigned int addrlen,
                  struct sockaddr* bind_addr, unsigned int* bind_addrlen,
                  struct sockopt* sockopt) {
    int retval = 0;
    unsigned int copied;
    unsigned int bind_len = bind_addrlen ? *bind_addrlen : 0;
    ms_ocall_connect_t* ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_ipv6_v6only = ipv6_v6only;
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addrlen = bind_len;
    ms->ms_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    ms->ms_bind_addr = bind_addr ? sgx_copy_to_ustack(bind_addr, bind_len) : NULL;

    if ((addr && !ms->ms_addr) || (bind_addr && !ms->ms_bind_addr)) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_CONNECT, ms);

    if (retval >= 0) {
        if (bind_addr && bind_len) {
            copied = sgx_copy_to_enclave(bind_addr, bind_len, ms->ms_bind_addr, ms->ms_bind_addrlen);
            if (!copied) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *bind_addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

ssize_t ocall_recv(int sockfd, void* buf, size_t count,
                   struct sockaddr* addr, unsigned int* addrlenptr,
                   void* control, uint64_t* controllenptr)
{
    ssize_t retval = 0;
    void * obuf = NULL;
    unsigned int copied;
    unsigned int addrlen = addrlenptr ? *addrlenptr : 0;
    uint64_t controllen  = controllenptr ? *controllenptr : 0;
    ms_ocall_recv_t * ms;
    bool need_munmap = false;

    if ((count + addrlen + controllen) > MAX_UNTRUSTED_STACK_BUF) {
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
        if (IS_ERR(retval))
            return retval;
    }

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = addrlen;
    ms->ms_addr = addr ? sgx_alloc_on_ustack_aligned(addrlen, alignof(*addr)) : NULL;
    ms->ms_controllen = controllen;
    ms->ms_control = control ? sgx_alloc_on_ustack(controllen) : NULL;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = sgx_alloc_on_ustack(count);

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_exitless_ocall(OCALL_RECV, ms);

    if (retval >= 0) {
        if (addr && addrlen) {
            copied = sgx_copy_to_enclave(addr, addrlen, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                retval = -EPERM;
                goto out;
            }
            *addrlenptr = copied;
        }

        if (control && controllen) {
            copied = sgx_copy_to_enclave(control, controllen, ms->ms_control, ms->ms_controllen);
            if (!copied) {
                retval = -EPERM;
                goto out;
            }
            *controllenptr = copied;
        }

        if (retval > 0 && !sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_send (int sockfd, const void* buf, size_t count,
                    const struct sockaddr* addr, unsigned int addrlen,
                    void* control, uint64_t controllen)
{
    ssize_t retval = 0;
    void * obuf = NULL;
    ms_ocall_send_t * ms;
    bool need_munmap;

    if (sgx_is_completely_outside_enclave(buf, count)) {
        /* buf is in untrusted memory (e.g., allowed file mmaped in untrusted memory) */
        obuf = (void*)buf;
    } else if (sgx_is_completely_within_enclave(buf, count)) {
        /* typical case of buf inside of enclave memory */
        if ((count + addrlen + controllen) > MAX_UNTRUSTED_STACK_BUF) {
            /* buf is too big and may overflow untrusted stack, so use untrusted heap */
            retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
            if (IS_ERR(retval))
                return retval;
            memcpy(obuf, buf, count);
        }
    } else {
        /* buf is partially in/out of enclave memory */
        return -EPERM;
    }

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = addrlen;
    ms->ms_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    ms->ms_controllen = controllen;
    ms->ms_control = control ? sgx_copy_to_ustack(control, controllen) : NULL;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = sgx_copy_to_ustack(buf, count);

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_exitless_ocall(OCALL_SEND, ms);

out:
    sgx_reset_ustack(old_ustack);
    if (obuf && obuf != buf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

int ocall_setsockopt (int sockfd, int level, int optname,
                      const void * optval, unsigned int optlen)
{
    int retval = 0;
    ms_ocall_setsockopt_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optlen = 0;
    ms->ms_optval = NULL;

    if (optval && optlen > 0) {
        ms->ms_optlen = optlen;
        ms->ms_optval = sgx_copy_to_ustack(optval, optlen);

        if (!ms->ms_optval) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    }

    retval = sgx_exitless_ocall(OCALL_SETSOCKOPT, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_shutdown (int sockfd, int how)
{
    int retval = 0;
    ms_ocall_shutdown_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = sgx_exitless_ocall(OCALL_SHUTDOWN, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_gettime_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    do {
        retval = sgx_exitless_ocall(OCALL_GETTIME, ms);
    } while(retval == -EINTR);
    if (!retval)
        *microsec = ms->ms_microsec;

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_sleep_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_microsec = microsec ? *microsec : 0;

    /* NOTE: no reason to use exitless for sleep() */
    retval = sgx_ocall(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_poll(struct pollfd* fds, int nfds, int64_t timeout_us) {
    int retval = 0;
    unsigned int nfds_bytes = nfds * sizeof(struct pollfd);
    ms_ocall_poll_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_nfds = nfds;
    ms->ms_timeout_us = timeout_us;
    ms->ms_fds = sgx_copy_to_ustack(fds, nfds_bytes);

    if (!ms->ms_fds) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_POLL, ms);

    if (retval >= 0) {
        if (!sgx_copy_to_enclave(fds, nfds_bytes, ms->ms_fds, nfds_bytes)) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;
    ms_ocall_rename_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_oldpath = sgx_copy_to_ustack(oldpath, oldlen);
    ms->ms_newpath = sgx_copy_to_ustack(newpath, newlen);

    if (!ms->ms_oldpath || !ms->ms_newpath) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_RENAME, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_delete_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);
    if (!ms->ms_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_DELETE, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    int len = strlen(command) + 1;

    void* old_ustack = sgx_prepare_ustack();
    const char * ms = sgx_copy_to_ustack(command, len);
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    retval = sgx_exitless_ocall(OCALL_LOAD_DEBUG, (void *) ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_eventfd (unsigned int initval, int flags)
{
    int retval = 0;
    ms_ocall_eventfd_t * ms;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    ms->ms_initval = initval;
    ms->ms_flags   = flags;

    retval = sgx_exitless_ocall(OCALL_EVENTFD, ms);

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_get_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                    const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len) {
    int retval;
    ms_ocall_get_quote_t* ms;
    char* buf = NULL;

    void* old_ustack = sgx_prepare_ustack();
    ms = sgx_alloc_on_ustack_aligned(sizeof(*ms), alignof(*ms));
    if (!ms) {
        retval = -ENOMEM;
        goto out;
    }

    memcpy(&ms->ms_spid, spid, sizeof(*spid));
    memcpy(&ms->ms_report, report, sizeof(*report));
    memcpy(&ms->ms_nonce, nonce, sizeof(*nonce));
    ms->ms_linkable = linkable;

    retval = sgx_exitless_ocall(OCALL_GET_QUOTE, ms);

    if (!IS_ERR(retval)) {
        ms_ocall_get_quote_t ms_copied;
        if (!sgx_copy_to_enclave(&ms_copied, sizeof(ms_copied), ms, sizeof(*ms))) {
            retval = -EACCES;
            goto out;
        }

        /* copy each field inside and free the out-of-enclave buffers */
        if (ms_copied.ms_quote) {
            size_t len = ms_copied.ms_quote_len;
            if (len > SGX_QUOTE_MAX_SIZE) {
                retval = -EACCES;
                goto out;
            }

            buf = malloc(len);
            if (!buf) {
                retval = -ENOMEM;
                goto out;
            }

            if (!sgx_copy_to_enclave(buf, len, ms_copied.ms_quote, len)) {
                retval = -EACCES;
                goto out;
            }

            retval = ocall_munmap_untrusted(ms_copied.ms_quote, ALLOC_ALIGN_UP(len));
            if (IS_ERR(retval)) {
                goto out;
            }

            *quote     = buf;
            *quote_len = len;
        }
    }

out:
    if (IS_ERR(retval))
        free(buf);
    sgx_reset_ustack(old_ustack);
    return retval;
}
