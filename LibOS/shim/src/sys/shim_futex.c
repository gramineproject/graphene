/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_futex.c
 *
 * Implementation of system call "futex", "set_robust_list" and
 * "get_robust_list".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_checkpoint.h>
#include <shim_utils.h>

#include <pal.h>
#include <pal_error.h>
#include <linux_list.h>

#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <linux/futex.h>
#include <errno.h>

#define FUTEX_MIN_VALUE 0
#define FUTEX_MAX_VALUE 255

struct futex_waiter {
    struct shim_thread * thread;
    uint32_t bitset;
    struct list_head list;
};

static LIST_HEAD(futex_list);
static LOCKTYPE futex_list_lock;

int shim_do_futex (unsigned int * uaddr, int op, int val, void * utime,
                   unsigned int * uaddr2, int val3)
{
    struct shim_futex_handle * tmp = NULL, * futex = NULL, * futex2 = NULL;
    struct shim_handle * hdl = NULL, * hdl2 = NULL;
    uint32_t futex_op = (op & FUTEX_CMD_MASK);

    uint32_t val2 = 0;
    int ret = 0;

    if (!uaddr || ((uintptr_t) uaddr % sizeof(unsigned int)))
        return -EINVAL;

    create_lock_runtime(&futex_list_lock);
    lock(futex_list_lock);

    list_for_each_entry(tmp, &futex_list, list)
        if (tmp->uaddr == uaddr) {
            futex = tmp;
            break;
        }

    if (futex) {
        hdl = container_of(futex, struct shim_handle, info.futex);
        get_handle(hdl);
    } else {
        if (!(hdl = get_new_handle())) {
            unlock(futex_list_lock);
            return -ENOMEM;
        }

        hdl->type = TYPE_FUTEX;
        futex = &hdl->info.futex;
        futex->uaddr = uaddr;
        get_handle(hdl);
        INIT_LIST_HEAD(&futex->waiters);
        INIT_LIST_HEAD(&futex->list);
        list_add_tail(&futex->list, &futex_list);
    }

    if (futex_op == FUTEX_WAKE_OP || futex_op == FUTEX_REQUEUE) {
        list_for_each_entry(tmp, &futex_list, list)
            if (tmp->uaddr == uaddr2) {
                futex2 = tmp;
                break;
            }

        if (futex2) {
            hdl2 = container_of(futex2, struct shim_handle, info.futex);
            get_handle(hdl2);
        } else {
            if (!(hdl2 = get_new_handle())) {
                unlock(futex_list_lock);
                return -ENOMEM;
            }

            hdl2->type = TYPE_FUTEX;
            futex2 = &hdl2->info.futex;
            futex2->uaddr = uaddr2;
            get_handle(hdl2);
            INIT_LIST_HEAD(&futex2->waiters);
            INIT_LIST_HEAD(&futex2->list);
            list_add_tail(&futex2->list, &futex_list);
        }

        val2 = (uint32_t)(uint64_t) utime;
    }

    unlock(futex_list_lock);
    lock(hdl->lock);

    switch (futex_op) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET: {
            uint32_t bitset = (futex_op == FUTEX_WAIT_BITSET) ? val3 :
                              0xffffffff;
            uint64_t timeout_us = NO_TIMEOUT;
            
            debug("FUTEX_WAIT: %p (val = %d) vs %d mask = %08x, timeout ptr %p\n",
                  uaddr, *uaddr, val, bitset, utime);

            if (*uaddr != val) {
                ret = -EAGAIN;
                break;
            }

            struct futex_waiter waiter;
            thread_setwait(&waiter.thread, NULL);
            INIT_LIST_HEAD(&waiter.list);
            waiter.bitset = bitset;
            list_add_tail(&waiter.list, &futex->waiters);

            unlock(hdl->lock);
            if (utime) {
                struct timespec *ts = (struct timespec*) utime;
                // Round to microsecs
                timeout_us = (ts->tv_sec * 1000000) + (ts->tv_nsec / 1000);
                // Check for the CLOCK_REALTIME flag
                if (futex_op == FUTEX_WAIT_BITSET)  {
                    // DEP 1/28/17: Should really differentiate clocks, but
                    // Graphene only has one for now.
                    //&& 0 != (op & FUTEX_CLOCK_REALTIME)) {
                    uint64_t current_time = DkSystemTimeQuery();
                    if (current_time == 0) {
                        ret = -EINVAL;
                        break;
                    }
                    timeout_us -= current_time;
                }
            }
            ret = thread_sleep(timeout_us);
            /* DEP 1/28/17: Should return ETIMEDOUT, not EAGAIN, on timeout. */
            if (ret == -EAGAIN)
                ret = -ETIMEDOUT;
            lock(hdl->lock);
            break;
        }

        case FUTEX_WAKE:
        case FUTEX_WAKE_BITSET: {
            uint32_t bitset = (futex_op == FUTEX_WAKE_BITSET) ? val3 :
                              0xffffffff;
            debug("FUTEX_WAKE: %p (val = %d) count = %d mask = %08x\n",
                  uaddr, *uaddr, val, bitset);
            int cnt, nwaken = 0;
            for (cnt = 0 ; cnt < val ; cnt++) {
                if (list_empty(&futex->waiters))
                    break;

                // BUG: if the first entry in the list isn't eligible, do we
                // ever wake anything up? doesn't this check the first entry
                // over and over?
                struct futex_waiter * waiter = list_entry(futex->waiters.next,
                                                          struct futex_waiter,
                                                          list);

                if (!(bitset & waiter->bitset))
                    continue;

                debug("FUTEX_WAKE wake thread %d: %p (val = %d)\n",
                      waiter->thread->tid, uaddr, *uaddr);
                list_del(&waiter->list);
                thread_wakeup(waiter->thread);
                nwaken++;
            }

            ret = nwaken;
            debug("FUTEX_WAKE done: %p (val = %d)\n", uaddr, *uaddr);
            break;
        }

        case FUTEX_WAKE_OP: {
            assert(futex2);
            int oldval = *(int *) uaddr2, newval, cmpval;

            newval = (val3 >> 12) & 0xfff;
            switch ((val3 >> 28) & 0xf) {
                case FUTEX_OP_SET:  break;
                case FUTEX_OP_ADD:  newval = oldval + newval;  break;
                case FUTEX_OP_OR:   newval = oldval | newval;  break;
                case FUTEX_OP_ANDN: newval = oldval & ~newval; break;
                case FUTEX_OP_XOR:  newval = oldval ^ newval;  break;
            }

            cmpval = val3 & 0xfff;
            switch ((val3 >> 24) & 0xf) {
                case FUTEX_OP_CMP_EQ: cmpval = (oldval == cmpval); break;
                case FUTEX_OP_CMP_NE: cmpval = (oldval != cmpval); break;
                case FUTEX_OP_CMP_LT: cmpval = (oldval < cmpval);  break;
                case FUTEX_OP_CMP_LE: cmpval = (oldval <= cmpval); break;
                case FUTEX_OP_CMP_GT: cmpval = (oldval > cmpval);  break;
                case FUTEX_OP_CMP_GE: cmpval = (oldval >= cmpval); break;
            }

            *(int *) uaddr2 = newval;
            int cnt, nwaken = 0;
            debug("FUTEX_WAKE: %p (val = %d) count = %d\n", uaddr, *uaddr, val);
            for (cnt = 0 ; cnt < val ; cnt++) {
                if (list_empty(&futex->waiters))
                    break;

                struct futex_waiter * waiter = list_entry(futex->waiters.next,
                                                          struct futex_waiter,
                                                          list);

                debug("FUTEX_WAKE wake thread %d: %p (val = %d)\n",
                      waiter->thread->tid, uaddr, *uaddr);
                list_del(&waiter->list);
                thread_wakeup(waiter->thread);
                nwaken++;
            }

            if (cmpval) {
                unlock(hdl->lock);
                put_handle(hdl);
                hdl = hdl2;
                lock(hdl->lock);
                debug("FUTEX_WAKE: %p (val = %d) count = %d\n", uaddr2,
                      *uaddr2, val2);
                for (cnt = 0 ; cnt < val2 ; cnt++) {
                    if (list_empty(&futex2->waiters))
                        break;

                    struct futex_waiter * waiter = list_entry(futex2->waiters.next,
                                                              struct futex_waiter,
                                                              list);

                    debug("FUTEX_WAKE wake thread %d: %p (val = %d)\n",
                          waiter->thread->tid, uaddr2, *uaddr2);
                    list_del(&waiter->list);
                    thread_wakeup(waiter->thread);
                    nwaken++;
                }
            }
            ret = nwaken;
            break;
        }

        case FUTEX_CMP_REQUEUE:
            if (*uaddr != val3) {
                ret = -EAGAIN;
                break;
            }

        case FUTEX_REQUEUE: {
            assert(futex2);
            int cnt;
            for (cnt = 0 ; cnt < val ; cnt++) {
                if (list_empty(&futex->waiters))
                    break;

                struct futex_waiter * waiter = list_entry(futex->waiters.next,
                                                          struct futex_waiter,
                                                          list);

                list_del(&waiter->list);
                thread_wakeup(waiter->thread);
            }

            lock(hdl2->lock);
            list_splice_init(&futex->waiters, &futex2->waiters);
            unlock(hdl2->lock);
            put_handle(hdl2);
            ret = cnt;
            break;
        }

        case FUTEX_FD:
            ret = set_new_fd_handle(hdl, 0, NULL);
            break;

        default:
            debug("unsupported futex op: 0x%x\n", op);
            ret = -ENOSYS;
            break;
    }

    unlock(hdl->lock);
    put_handle(hdl);
    return ret;
}

int shim_do_set_robust_list (struct robust_list_head * head, size_t len)
{
    struct shim_thread * self = get_cur_thread();
    assert(self);

    if (len != sizeof(struct robust_list_head))
        return -EINVAL;

    self->robust_list = head;
    return 0;
}

int shim_do_get_robust_list (pid_t pid, struct robust_list_head ** head,
                             size_t * len)
{
    if (!head)
        return -EFAULT;

    struct shim_thread * thread;

    if (pid) {
        thread = lookup_thread(pid);
        if (!thread)
            return -ESRCH;
    } else {
        thread = get_cur_thread();
    }

    *head = (struct robust_list_head *) thread->robust_list;
    *len = sizeof(struct robust_list_head);
    return 0;
}

void release_robust_list (struct robust_list_head * head)
{
    long futex_offset = head->futex_offset;
    struct robust_list * robust, * prev = &head->list;

    create_lock_runtime(&futex_list_lock);

    for (robust = prev->next ; robust && robust != prev ;
         prev = robust, robust = robust->next) {
        void * futex_addr = (void *) robust + futex_offset;
        struct shim_futex_handle * tmp, * futex = NULL;

        lock(futex_list_lock);

        list_for_each_entry(tmp, &futex_list, list)
            if (tmp->uaddr == futex_addr) {
                futex = tmp;
                break;
            }

        unlock(futex_list_lock);

        if (!futex)
            continue;

        struct shim_handle * hdl =
            container_of(futex, struct shim_handle, info.futex);
        get_handle(hdl);
        lock(hdl->lock);

        debug("release robust list: %p\n", futex_addr);
        *(int *) futex_addr = 0;
        while (!list_empty(&futex->waiters)) {
            struct futex_waiter * waiter = list_entry(futex->waiters.next,
                                                      struct futex_waiter,
                                                      list);

            list_del(&waiter->list);
            thread_wakeup(waiter->thread);
        }

        unlock(hdl->lock);
        put_handle(hdl);
    }
}

void release_clear_child_id (int * clear_child_tid)
{
    debug("clear child tid at %p\n", clear_child_tid);
    *clear_child_tid = 0;

    create_lock_runtime(&futex_list_lock);

    struct shim_futex_handle * tmp, * futex = NULL;
    lock(futex_list_lock);

    list_for_each_entry(tmp, &futex_list, list)
        if (tmp->uaddr == (void *) clear_child_tid) {
            futex = tmp;
            break;
        }

    unlock(futex_list_lock);

    if (!futex)
        return;

    struct shim_handle * hdl =
            container_of(futex, struct shim_handle, info.futex);
    get_handle(hdl);
    lock(hdl->lock);

    debug("release futex at %p\n", clear_child_tid);
    *clear_child_tid = 0;
    while (!list_empty(&futex->waiters)) {
        struct futex_waiter * waiter = list_entry(futex->waiters.next,
                                                  struct futex_waiter,
                                                  list);

        list_del(&waiter->list);
        thread_wakeup(waiter->thread);
    }

    unlock(hdl->lock);
    put_handle(hdl);
}
