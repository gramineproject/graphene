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
 * shim_epoll.c
 *
 * Implementation of system call "execve".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_fs.h>
#include <shim_ipc.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <linux/futex.h>
#include <errno.h>

static int close_cloexec_handle (struct shim_handle_map * map)
{
    auto int close_on_exec (struct shim_fd_handle * fd_hdl,
                           struct shim_handle_map * map, void * arg)
    {
        if (fd_hdl->flags & FD_CLOEXEC) {
            struct shim_handle * hdl = __detach_fd_handle(fd_hdl, NULL, map);
            close_handle(hdl);
        }
        return 0;
    }

    return walk_handle_map(&close_on_exec, map, NULL);
}

DEFINE_PROFILE_CATAGORY(exec_rtld, exec);
DEFINE_PROFILE_INTERVAL(alloc_new_stack_for_exec, exec_rtld);
DEFINE_PROFILE_INTERVAL(arrange_arguments_for_exec, exec_rtld);
DEFINE_PROFILE_INTERVAL(unmap_executable_for_exec, exec_rtld);
DEFINE_PROFILE_INTERVAL(unmap_loaded_binaries_for_exec, exec_rtld);
DEFINE_PROFILE_INTERVAL(unmap_all_vmas_for_exec, exec_rtld);
DEFINE_PROFILE_INTERVAL(load_new_executable_for_exec, exec_rtld);

static void * old_stack_top, * old_stack, * old_stack_red;
static const char ** new_argp;
static int           new_argc;
static elf_auxv_t *  new_auxp;

#define REQUIRED_ELF_AUXV       6

int shim_do_execve_rtld (struct shim_handle * hdl, const char ** argv,
                         const char ** envp)
{
    BEGIN_PROFILE_INTERVAL();

    struct shim_thread * cur_thread = get_cur_thread();
    int ret;

    if ((ret = close_cloexec_handle(cur_thread->handle_map)) < 0)
        return ret;

    SAVE_PROFILE_INTERVAL(close_CLOEXEC_files_for_exec);

    void * tcb = malloc(sizeof(__libc_tcb_t));
    if (!tcb)
        return -ENOMEM;

    populate_tls(tcb);

    put_handle(cur_thread->exec);
    get_handle(hdl);
    cur_thread->exec = hdl;

    old_stack_top = cur_thread->stack_top;
    old_stack     = cur_thread->stack;
    old_stack_red = cur_thread->stack_red;
    cur_thread->stack_top = NULL;
    cur_thread->stack     = NULL;
    cur_thread->stack_red = NULL;

    initial_envp = NULL;
    new_argc = 0;
    for (const char ** a = argv ; *a ; a++, new_argc++);

    if ((ret = init_stack(argv, envp, &new_argp,
                          REQUIRED_ELF_AUXV, &new_auxp)) < 0)
        return ret;

    SAVE_PROFILE_INTERVAL(alloc_new_stack_for_exec);

    switch_stack(new_argp);
    cur_thread = get_cur_thread();

    UPDATE_PROFILE_INTERVAL();

    DkVirtualMemoryFree(old_stack, old_stack_top - old_stack);
    DkVirtualMemoryFree(old_stack_red, old_stack - old_stack_red);
    int flags = VMA_INTERNAL;
    bkeep_munmap(old_stack, old_stack_top - old_stack, &flags);
    bkeep_munmap(old_stack_red, old_stack - old_stack_red, &flags);

    remove_loaded_libraries();
    clean_link_map_list();
    SAVE_PROFILE_INTERVAL(unmap_loaded_binaries_for_exec);

    init_brk();
    unmap_all_vmas();
    SAVE_PROFILE_INTERVAL(unmap_all_vmas_for_exec);

    if ((ret = load_elf_object(cur_thread->exec, NULL, 0)) < 0)
        shim_terminate();

    load_elf_interp(cur_thread->exec);

    SAVE_PROFILE_INTERVAL(load_new_executable_for_exec);

    cur_thread->robust_list = NULL;

    debug("execve: start execution\n");
    execute_elf_object(cur_thread->exec, new_argc, new_argp,
                       REQUIRED_ELF_AUXV, new_auxp);

    return 0;
}

static void * __malloc (size_t size)
{
    int flags = MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL;
    size = ALIGN_UP(size);
    void * addr = get_unmapped_vma(size, flags);

    addr = DkVirtualMemoryAlloc(addr, size, 0, PAL_PROT_READ|PAL_PROT_WRITE);

    if (addr)
        bkeep_mmap(addr, size, PROT_READ|PROT_WRITE, flags, NULL, 0,
                   "checkpoint");

    return addr;
}

#define malloc_method __malloc
#include <shim_checkpoint.h>

DEFINE_PROFILE_CATAGORY(exec, );
DEFINE_PROFILE_INTERVAL(search_and_check_file_for_exec, exec);
DEFINE_PROFILE_INTERVAL(open_file_for_exec, exec);
DEFINE_PROFILE_INTERVAL(close_CLOEXEC_files_for_exec, exec);

static int migrate_execve (struct shim_cp_store * cpstore,
                           struct shim_process * process,
                           struct shim_thread * thread, va_list ap)
{
    struct shim_handle_map * handle_map = NULL;
    int ret;
    const char ** envp = va_arg (ap, const char **);
    size_t envsize = va_arg (ap, size_t);

    BEGIN_PROFILE_INTERVAL();

    if ((ret = dup_handle_map(&handle_map, thread->handle_map)) < 0)
        return ret;

    set_handle_map(thread, handle_map);

    if ((ret = close_cloexec_handle(handle_map)) < 0)
        return ret;

    SAVE_PROFILE_INTERVAL(close_CLOEXEC_files_for_exec);

    /* Now we start to migrate bookkeeping for exec.
       The data we need to migrate are:
            1. cur_threadrent thread
            2. cur_threadrent filesystem
            3. handle mapping
            4. each handle              */
    BEGIN_MIGRATION_DEF(execve, struct shim_process * proc,
                        struct shim_thread * thread,
                        const char ** envp, size_t envsize)
    {
        store->use_gipc = true;
        DEFINE_MIGRATE(process, proc, sizeof(struct shim_process), false);
        DEFINE_MIGRATE(all_mounts, NULL, 0, false);
        DEFINE_MIGRATE(running_thread, thread, sizeof(struct shim_thread),
                       false);
        DEFINE_MIGRATE(handle_map, thread->handle_map,
                       sizeof (struct shim_handle_map), true);
        DEFINE_MIGRATE(migratable, NULL, 0, false);
        DEFINE_MIGRATE(environ, envp, envsize, true);
    }
    END_MIGRATION_DEF

    return START_MIGRATE(cpstore, execve, 0, process, thread, envp, envsize);
}

int shim_do_execve (const char * file, const char ** argv,
                    const char ** envp)
{
    struct shim_thread * cur_thread = get_cur_thread();
    struct shim_dentry * dent = NULL;
    int ret = 0;

    if (!envp)
        envp = initial_envp;

    BEGIN_PROFILE_INTERVAL();

    if ((ret = path_lookupat(NULL, file, LOOKUP_OPEN, &dent)) < 0)
        return ret;

    struct shim_mount * fs = dent->fs;
    get_dentry(dent);

    if (!fs->d_ops->open) {
        ret = -EACCES;
err:
        put_dentry(dent);
        return ret;
    }

    if (fs->d_ops->mode) {
        mode_t mode;
        if ((ret = fs->d_ops->mode(dent, &mode, 1)) < 0)
            goto err;
    }

    SAVE_PROFILE_INTERVAL(search_and_check_file_for_exec);

    struct shim_handle * exec = NULL;

    if (!(exec = get_new_handle())) {
        ret = -ENOMEM;
        goto err;
    }

    set_handle_fs(exec, fs);
    exec->flags = O_RDONLY;
    exec->acc_mode = MAY_READ;
    ret = fs->d_ops->open(exec, dent, O_RDONLY);

    if (qstrempty(&exec->uri)) {
        put_handle(exec);
        return -EACCES;
    }

    int sz;
    char *path = dentry_get_path(dent, true, &sz);
    qstrsetstr(&exec->path, path, sz);

    if ((ret = check_elf_object(&exec)) < 0) {
        put_handle(exec);
        return ret;
    }

    SAVE_PROFILE_INTERVAL(open_file_for_exec);

    int is_last = check_last_thread(cur_thread) == 0;
    if (is_last)
        return shim_do_execve_rtld(exec, argv, envp);

    INC_PROFILE_OCCURENCE(syscall_use_ipc);

#ifdef PROFILE
    unsigned long create_time = GET_PROFILE_INTERVAL();
#endif

    size_t envsize = allocsize;
    void * envptr = NULL;
    const char ** empty_argv = NULL;
retry:
    envptr = system_malloc(envsize);
    if (!envptr)
        return -ENOMEM;

    ret = populate_user_stack(envptr, envsize, 0, NULL, &empty_argv, &envp);
    if (ret == -ENOMEM) {
        system_free(envptr, envsize);
        envsize += allocsize;
        goto retry;
    }

    lock(cur_thread->lock);
    put_handle(cur_thread->exec);
    cur_thread->exec = exec;

    void * stack     = cur_thread->stack;
    void * stack_top = cur_thread->stack_top;
    void * tcb       = cur_thread->tcb;
    void * frameptr  = cur_thread->frameptr;

    cur_thread->stack     = NULL;
    cur_thread->stack_top = NULL;
    cur_thread->frameptr  = NULL;
    cur_thread->tcb       = NULL;
    cur_thread->in_vm     = false;
    unlock(cur_thread->lock);

    ret = do_migrate_process(&migrate_execve, exec, argv, cur_thread, envp,
                             envptr + envsize - (void *) envp);

    system_free(envptr, envsize);

    lock(cur_thread->lock);
    cur_thread->stack       = stack;
    cur_thread->stack_top   = stack_top;
    cur_thread->frameptr    = frameptr;
    cur_thread->tcb         = tcb;

    if (ret < 0) {
        cur_thread->in_vm = true;
        unlock(cur_thread->lock);
        return ret;
    }

    struct shim_handle_map * handle_map = cur_thread->handle_map;
    cur_thread->handle_map = NULL;
    unlock(cur_thread->lock);
    if (handle_map)
        put_handle_map(handle_map);

    if (cur_thread->dummy)
        switch_dummy_thread(cur_thread);

    try_process_exit(0);
    return 0;
}
