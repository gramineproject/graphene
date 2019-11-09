/* Copyright (C) 2014 Stony Brook University
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
 * shim_vfork.c
 *
 * Implementation of system call "vfork".
 */

#include <asm/prctl.h>
#include <errno.h>
#include <linux/futex.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <sys/mman.h>
#include <sys/syscall.h>

int shim_do_vfork(void) {
#ifdef ALIAS_VFORK_AS_FORK
    debug("vfork() is an alias to fork() in Graphene, calling fork() now\n");
    return shim_do_fork();
#else
    /* NOTE: leaving this old implementation for historical reference */
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    /* DEP 7/7/12 - Why r13?
     *
     * Chia-che: when libc call vfork, they store the pointer to the
     * caller in rdi. (reference: sysdeps/unix/sysv/linux/x86_64/vfork.S.
     * Because rdi might be used in SHIM, I cache rdi in r13 (reference:
     * syscallas.S).
     */
    struct shim_thread* cur_thread = get_cur_thread();
    struct shim_thread* new_thread = get_new_thread(0);
    /* put the new thread in a new process (thread group) */

    __asm__ volatile ("movq %%rbp, %0\r\n" : "=r"(new_thread->frameptr));

    size_t stack_size = 4096;

    if (new_thread->frameptr <= cur_thread->stack_top && new_thread->frameptr > cur_thread->stack)
        stack_size = cur_thread->stack_top - new_thread->frameptr;

    void* dummy_stack = system_malloc(stack_size);

    if (!dummy_stack) {
        debug("creation of stack failed\n");
        put_thread(new_thread);
        return -PAL_ERRNO;
    }

    memcpy(dummy_stack, new_thread->frameptr, stack_size);

    /* assigned the stack of the thread */
    lock(&cur_thread->lock);
    new_thread->tgid      = new_thread->tid;
    new_thread->in_vm     = true;
    new_thread->is_alive  = true;
    new_thread->stack     = cur_thread->stack;
    new_thread->stack_top = cur_thread->stack_top;
    cur_thread->stack     = dummy_stack;
    cur_thread->stack_top = dummy_stack + stack_size;
    cur_thread->frameptr  = NULL;
    unlock(&cur_thread->lock);

    /* Now we are good, set this child as ours */
    set_as_child(NULL, new_thread);
    /* add the child to the global list */
    add_thread(new_thread);
    new_thread->dummy = cur_thread;

    struct shim_handle_map* handle_map = get_cur_handle_map(cur_thread);
    /* pop the ref count of current handle map to prevent revocation */
    get_handle_map(handle_map);
    struct shim_handle_map* new_map = NULL;
    /* duplicate handle map intp a new handle map */
    dup_handle_map(&new_map, handle_map);
    /* set the new handle map to new thread */
    set_handle_map(new_thread, new_map);
    /* push back the ref count of handle map */
    put_handle_map(handle_map);

    /* we have the thread handle from PAL, now set it to the child */
    new_thread->pal_handle = cur_thread->pal_handle;

    /* set the current thread running */
    set_cur_thread(new_thread);
    put_thread(new_thread);

    /* here we return immediately, no letting the hooks mes up our stack */
    return 0;
#endif
}
