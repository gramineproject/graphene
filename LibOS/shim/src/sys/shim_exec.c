/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "execve".
 */

#include <errno.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_vma.h"
#include "stat.h"

/* returns 0 if normalized URIs are the same; assumes file URIs */
static int normalize_and_cmp_uris(const char* uri1, const char* uri2) {
    char norm1[STR_SIZE];
    char norm2[STR_SIZE];
    size_t len;
    int ret;

    if (!strstartswith(uri1, URI_PREFIX_FILE) || !strstartswith(uri2, URI_PREFIX_FILE))
        return -1;

    uri1 += URI_PREFIX_FILE_LEN;
    len = sizeof(norm1);
    ret = get_norm_path(uri1, norm1, &len);
    if (ret < 0)
        return ret;

    uri2 += URI_PREFIX_FILE_LEN;
    len = sizeof(norm2);
    ret = get_norm_path(uri2, norm2, &len);
    if (ret < 0)
        return ret;

    return memcmp(norm1, norm2, len + 1);
}

static int close_on_exec(struct shim_fd_handle* fd_hdl, struct shim_handle_map* map) {
    if (fd_hdl->flags & FD_CLOEXEC) {
        struct shim_handle* hdl = __detach_fd_handle(fd_hdl, NULL, map);
        put_handle(hdl);
    }
    return 0;
}

static int close_cloexec_handle(struct shim_handle_map* map) {
    return walk_handle_map(&close_on_exec, map);
}

struct execve_rtld_arg {
    void* new_argp;       /* pointer to beginning of first stack frame (argc, argv[0], ...) */
    elf_auxv_t* new_auxv; /* pointer inside first stack frame (auxv[0], auxv[1], ...) */
};

noreturn static void __shim_do_execve_rtld(struct execve_rtld_arg* __arg) {
    struct execve_rtld_arg arg = *__arg;

    struct shim_thread* cur_thread = get_cur_thread();
    int ret = 0;

    unsigned long tls_base = 0;
    update_tls_base(tls_base);
    debug("set tls_base to 0x%lx\n", tls_base);

    thread_sigaction_reset_on_execve(cur_thread);

    remove_loaded_libraries();
    clean_link_map_list();

    reset_brk();

    size_t count;
    struct shim_vma_info* vmas;
    ret = dump_all_vmas(&vmas, &count, /*include_unmapped=*/true);
    if (ret < 0) {
        goto error;
    }

    for (struct shim_vma_info* vma = vmas; vma < vmas + count; vma++) {
        /* Don't free the current stack */
        if (vma->addr == cur_thread->stack || vma->addr == cur_thread->stack_red)
            continue;

        void* tmp_vma = NULL;
        if (bkeep_munmap(vma->addr, vma->length, !!(vma->flags & VMA_INTERNAL), &tmp_vma) < 0) {
            BUG();
        }
        DkVirtualMemoryFree(vma->addr, vma->length);
        bkeep_remove_tmp_vma(tmp_vma);
    }

    free_vma_info_array(vmas, count);

    lock(&g_process.fs_lock);
    struct shim_handle* exec = g_process.exec;
    get_handle(exec);
    unlock(&g_process.fs_lock);

    if ((ret = load_elf_object(exec, NULL, 0)) < 0)
        goto error;

    if ((ret = init_brk_from_executable(exec)) < 0)
        goto error;

    load_elf_interp(exec);

    cur_thread->robust_list = NULL;

    debug("execve: start execution\n");
    /* Passing ownership of `exec` to `execute_elf_object`. */
    execute_elf_object(exec, arg.new_argp, arg.new_auxv);
    /* NOTREACHED */

error:
    debug("execve: failed %d\n", ret);
    process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
}

static int shim_do_execve_rtld(struct shim_handle* hdl, const char** argv, const char** envp) {
    struct shim_thread* cur_thread = get_cur_thread();
    int ret;

    if ((ret = close_cloexec_handle(cur_thread->handle_map)) < 0)
        return ret;

    lock(&g_process.fs_lock);
    put_handle(g_process.exec);
    get_handle(hdl);
    g_process.exec = hdl;
    unlock(&g_process.fs_lock);

    cur_thread->stack_top = NULL;
    cur_thread->stack     = NULL;
    cur_thread->stack_red = NULL;

    migrated_argv = NULL;
    migrated_envp = NULL;

    const char** new_argp;
    elf_auxv_t* new_auxv;
    ret = init_stack(argv, envp, &new_argp, &new_auxv);
    if (ret < 0)
        return ret;

    /* We are done using this handle and we got the ownership from the caller. */
    put_handle(hdl);

    struct execve_rtld_arg arg = {
        .new_argp = new_argp,
        .new_auxv = new_auxv
    };
    __SWITCH_STACK(new_argp, &__shim_do_execve_rtld, &arg);
    /* UNREACHABLE */
}

static BEGIN_MIGRATION_DEF(execve, struct shim_process* process_description,
                           struct shim_thread* thread_description,
                           struct shim_process_ipc_info* process_ipc_info,
                           const char** argv, const char** envp) {
    DEFINE_MIGRATE(process_ipc_info, process_ipc_info, sizeof(struct shim_process_ipc_info));
    DEFINE_MIGRATE(all_mounts, NULL, 0);
    DEFINE_MIGRATE(process_description, process_description, sizeof(*process_description));
    DEFINE_MIGRATE(thread, thread_description, sizeof(*thread_description));
    DEFINE_MIGRATE(pending_signals, NULL, 0);
    DEFINE_MIGRATE(migratable, NULL, 0);
    DEFINE_MIGRATE(arguments, argv, 0);
    DEFINE_MIGRATE(environ, envp, 0);
    DEFINE_MIGRATE(groups_info, NULL, 0);
}
END_MIGRATION_DEF(execve)

static int migrate_execve(struct shim_cp_store* cpstore, struct shim_process* process_description,
                          struct shim_thread* thread_description,
                          struct shim_process_ipc_info* process_ipc_info, va_list ap) {
    const char** argv = va_arg(ap, const char**);
    const char** envp = va_arg(ap, const char**);

    return START_MIGRATE(cpstore, execve, process_description, thread_description, process_ipc_info,
                         argv, envp);
}

int shim_do_execve(const char* file, const char** argv, const char** envp) {
    struct shim_thread* cur_thread = get_cur_thread();
    struct shim_dentry* dent       = NULL;
    int ret = 0, argc = 0;

    if (test_user_string(file))
        return -EFAULT;

    for (const char** a = argv; /* no condition*/; a++, argc++) {
        if (test_user_memory(a, sizeof(*a), false))
            return -EFAULT;
        if (*a == NULL)
            break;
        if (test_user_string(*a))
            return -EFAULT;
    }

    if (!envp)
        envp = migrated_envp;

    for (const char** e = envp; /* no condition*/; e++) {
        if (test_user_memory(e, sizeof(*e), false))
            return -EFAULT;
        if (*e == NULL)
            break;
        if (test_user_string(*e))
            return -EFAULT;
    }

    DEFINE_LIST(sharg);
    struct sharg {
        LIST_TYPE(sharg) list;
        int len;
        char arg[0];
    };
    DEFINE_LISTP(sharg);
    LISTP_TYPE(sharg) shargs;
    INIT_LISTP(&shargs);

reopen:

    /* XXX: Not sure what to do here yet */
    assert(cur_thread);
    if ((ret = path_lookupat(NULL, file, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    struct shim_mount* fs = dent->fs;
    get_dentry(dent);

    if (!fs->d_ops->open) {
        ret = -EACCES;
    err:
        put_dentry(dent);
        return ret;
    }

    if (fs->d_ops->mode) {
        __kernel_mode_t mode;
        if ((ret = fs->d_ops->mode(dent, &mode)) < 0)
            goto err;
        /* Check if the file is executable. Currently just looks at the user bit. */
        if (!(mode & S_IXUSR)) {
            ret = -EACCES;
            goto err;
        }
    }

    struct shim_handle* exec = NULL;

    if (!(exec = get_new_handle())) {
        ret = -ENOMEM;
        goto err;
    }

    set_handle_fs(exec, fs);
    exec->flags    = O_RDONLY;
    exec->acc_mode = MAY_READ;
    ret = fs->d_ops->open(exec, dent, O_RDONLY);

    if (qstrempty(&exec->uri)) {
        put_handle(exec);
        return -EACCES;
    }

    dentry_get_path_into_qstr(dent, &exec->path);

    if ((ret = check_elf_object(exec)) < 0 && ret != -EINVAL) {
        put_handle(exec);
        return ret;
    }

    if (ret == -EINVAL) { /* it's a shebang */
        LISTP_TYPE(sharg) new_shargs = LISTP_INIT;
        struct sharg* next = NULL;
        bool ended = false, started = false;
        char buf[80];

        do {
            ret = do_handle_read(exec, buf, 80);
            if (ret <= 0)
                break;

            char* s = buf;
            char* c = buf;
            char* e = buf + ret;

            if (!started) {
                if (ret < 2 || buf[0] != '#' || buf[1] != '!')
                    break;

                s += 2;
                c += 2;
                started = true;
            }

            for (; c < e; c++) {
                if (*c == ' ' || *c == '\n' || c == e - 1) {
                    int l = (*c == ' ' || *c == '\n') ? c - s : e - s;
                    if (next) {
                        struct sharg* sh = __alloca(sizeof(struct sharg) + next->len + l + 1);
                        sh->len = next->len + l;
                        memcpy(sh->arg, next->arg, next->len);
                        memcpy(sh->arg + next->len, s, l);
                        sh->arg[next->len + l] = 0;
                        next = sh;
                    } else {
                        next = __alloca(sizeof(struct sharg) + l + 1);
                        next->len = l;
                        memcpy(next->arg, s, l);
                        next->arg[l] = 0;
                    }
                    if (*c == ' ' || *c == '\n') {
                        INIT_LIST_HEAD(next, list);
                        LISTP_ADD_TAIL(next, &new_shargs, list);
                        next = NULL;
                        s = c + 1;
                        if (*c == '\n') {
                            ended = true;
                            break;
                        }
                    }
                }
            }
        } while (!ended);

        if (!started) {
            debug("file not recognized as ELF or shebang");
            put_handle(exec);
            return -ENOEXEC;
        }

        if (next) {
            INIT_LIST_HEAD(next, list);
            LISTP_ADD_TAIL(next, &new_shargs, list);
        }

        struct sharg* first = LISTP_FIRST_ENTRY(&new_shargs, struct sharg, list);
        assert(first);
        debug("detected as script: run by %s\n", first->arg);
        file = first->arg;
        LISTP_SPLICE(&new_shargs, &shargs, list, sharg);
        put_handle(exec);
        goto reopen;
    }

    /* If `execve` is invoked concurrently by multiple threads, let only one succeed. From this
     * point errors are fatal. */
    static unsigned int first = 0;
    if (__atomic_exchange_n(&first, 1, __ATOMIC_RELAXED) != 0) {
        /* Just exit current thread. */
        thread_exit(/*error_code=*/0, /*term_signal=*/0);
    }
    (void)kill_other_threads();

    /* All other threads are dead. Restoring initial value in case we stay inside same process
     * instance and call execve again. */
    __atomic_store_n(&first, 0, __ATOMIC_RELAXED);

    /* Disable preemption during `execve`. It will be enabled back in `execute_elf_object` if we
     * stay in the same process. Otherwise it is never enabled, since this process dies both on
     * errors and success. */
    disable_preempt(NULL);

    bool use_same_process = true;
    if (!strcmp(PAL_CB(host_type), "Linux-SGX")) {
        /* for SGX PALs, can use same process only if it is the same executable (because a different
         * executable has a different measurement and thus requires a new enclave); this special
         * case is to correctly handle e.g. Bash process replacing itself */
        lock(&g_process.fs_lock);
        assert(g_process.exec);
        if (normalize_and_cmp_uris(qstrgetstr(&g_process.exec->uri), qstrgetstr(&exec->uri))) {
            /* it is not the same executable, definitely cannot use same process */
            use_same_process = false;
        }
        unlock(&g_process.fs_lock);
    }

    if (use_same_process) {
        debug("execve() in the same process\n");
        /* Passing ownership of `exec`. */
        ret = shim_do_execve_rtld(exec, argv, envp);
        assert(ret < 0);
        goto out_fatal_error;
    }
    debug("execve() in a new process\n");

    if (!LISTP_EMPTY(&shargs)) {
        struct sharg* sh;
        int shargc = 0, cnt = 0;
        LISTP_FOR_EACH_ENTRY(sh, &shargs, list) {
            shargc++;
        }

        const char** new_argv = __alloca(sizeof(const char*) * (argc + shargc + 1));

        LISTP_FOR_EACH_ENTRY(sh, &shargs, list) {
            new_argv[cnt++] = sh->arg;
        }

        for (cnt = 0; cnt < argc; cnt++)
            new_argv[shargc + cnt] = argv[cnt];

        new_argv[shargc + argc] = NULL;
        argv                    = new_argv;
    }

    /* Pause IPC helper not to receive any child exit messages - all of them will be handled in
     * the new process (after execve). */
    ret = pause_ipc_helper();
    if (ret < 0) {
        goto out_fatal_error;
    }
    /* TODO: we should also terminate async helper, serialize it's state (pending alarms etc.) and
     * send to the new process. */

    /* We are the only thread running and IPC helper thread is blocked, so there is no need for
     * locking `cur_thread` and `g_process` and we can safely reuse them as arguments to
     * `create_process_and_send_checkpoint` below. */

    void* stack          = cur_thread->stack;
    void* stack_top      = cur_thread->stack_top;
    shim_tcb_t* shim_tcb = cur_thread->shim_tcb;
    void* frameptr       = cur_thread->frameptr;

    cur_thread->stack     = NULL;
    cur_thread->stack_top = NULL;
    cur_thread->frameptr  = NULL;
    cur_thread->shim_tcb  = NULL;

    ret = close_cloexec_handle(cur_thread->handle_map);
    if (ret < 0) {
        goto out_fatal_error_resume_ipc;
    }

    struct shim_handle* old_exec = g_process.exec;
    g_process.exec = exec;

    ret = create_process_and_send_checkpoint(&migrate_execve, exec, /*child_process=*/NULL,
                                             &g_process, cur_thread, argv, envp);

    g_process.exec = old_exec;

    lock(&cur_thread->lock);
    cur_thread->stack     = stack;
    cur_thread->stack_top = stack_top;
    cur_thread->frameptr  = frameptr;
    cur_thread->shim_tcb  = shim_tcb;
    unlock(&cur_thread->lock);

    if (ret < 0) {
        goto out_fatal_error_resume_ipc;
    }

    /* this "temporary" process must die quietly, not sending any messages to not confuse the parent
     * and the execve'ed child, but it must still be around until the child finally exits (because
     * its parent in turn may wait on it, e.g., `bash -c ls`) */
    debug(
        "Temporary process %u is exiting after emulating execve (by forking new process to replace"
        " this one); will wait for forked process to exit...\n", g_process_ipc_info.vmid & 0xFFFF);
    MASTER_LOCK();
    DkProcessExit(PAL_WAIT_FOR_CHILDREN_EXIT);
    /* UNREACHABLE */

out_fatal_error_resume_ipc:
    resume_ipc_helper();
out_fatal_error:
    put_handle(exec);
    /* We might have killed some threads and closed some fds and execve failed internally. User app
     * might now be in undefined state, we would better blow everything up. */
    process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
}
