/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "list.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_thread.h"
#include "shim_utils.h"

typedef bool (*child_cmp_t)(struct shim_child_process*, unsigned long);

struct shim_process g_process = { .pid = 0 };

int init_process(void) {
    if (g_process.pid) {
        /* `g_process` is already initialized, e.g. via checkpointing code. */
        return 0;
    }

    /* If init_* function fails, then the whole process should die, so we do not need to clean-up
     * on errors. */
    if (!create_lock(&g_process.children_lock)) {
        return -ENOMEM;
    }
    if (!create_lock(&g_process.fs_lock)) {
        return -ENOMEM;
    }

    /* `pid` and `pgid` are initialized together with the first thread. */
    g_process.ppid = 0;

    INIT_LISTP(&g_process.children);
    INIT_LISTP(&g_process.zombies);

    g_process.wait_queue = NULL;

    g_process.umask = 0;

    struct shim_dentry* dent = NULL;
    int ret = path_lookupat(NULL, "/", 0, &dent, NULL);
    if (ret < 0) {
        debug("Could not setup dentry for \"/\", something is seriously broken.\n");
        return ret;
    }
    g_process.root = dent;

    char dir_cfg[CONFIG_MAX];
    if (root_config && get_config(root_config, "fs.start_dir", dir_cfg, sizeof(dir_cfg)) > 0) {
        dent = NULL;
        ret = path_lookupat(NULL, dir_cfg, 0, &dent, NULL);
        if (ret < 0) {
            debug("Invalid \"fs.start_dir\" in manifest.\n");
            return ret;
        }
        g_process.cwd = dent;
    } else {
        get_dentry(g_process.root);
        g_process.cwd = g_process.root;
    }

    /* `g_process.exec` will be initialized later on (in `init_important_handles`). */
    g_process.exec = NULL;

    return 0;
}

struct shim_child_process* create_child_process(void) {
    struct shim_child_process* child = calloc(1, sizeof(*child));
    if (!child) {
        return NULL;
    }

    INIT_LIST_HEAD(child, list);

    return child;
}

void destroy_child_process(struct shim_child_process* child) {
    assert(LIST_EMPTY(child, list));

    free(child);
}

void add_child_process(struct shim_child_process* child) {
    assert(LIST_EMPTY(child, list));
    lock(&g_process.children_lock);
    LISTP_ADD(child, &g_process.children, list);
    unlock(&g_process.children_lock);
}

static bool cmp_child_by_vmid(struct shim_child_process* child, unsigned long arg) {
    IDTYPE vmid = (IDTYPE)arg;
    return child->vmid == vmid;
}

static bool cmp_child_by_pid(struct shim_child_process* child, unsigned long arg) {
    IDTYPE pid = (IDTYPE)arg;
    return child->pid == pid;
}

static bool mark_child_exited(child_cmp_t child_cmp, unsigned long arg, IDTYPE uid, int exit_code,
                              int signal) {
    bool ret = false;
    int parent_signal = 0;
    IDTYPE child_pid = 0;
    struct shim_thread_queue* wait_queue = NULL;

    lock(&g_process.children_lock);

    struct shim_child_process* child = NULL;
    struct shim_child_process* tmp = NULL;
    LISTP_FOR_EACH_ENTRY_SAFE(child, tmp, &g_process.children, list) {
        if (child_cmp(child, arg)) {
            child->exit_code = exit_code;
            child->term_signal = signal;
            child->uid = uid;

            LISTP_DEL_INIT(child, &g_process.children, list);
            /* TODO: if SIGCHLD is ignored or has SA_NOCLDWAIT flag set, then the child should not
             * become a zombie. */
            LISTP_ADD(child, &g_process.zombies, list);

            parent_signal = child->child_termination_signal;
            child_pid = child->pid;

            wait_queue = g_process.wait_queue;
            g_process.wait_queue = NULL;

            ret = true;
            break;
        }
    }

    /* We send signal to our process while still holding the lock, so that no thread is able to
     * see 0 pending signals but still get an exited child info. */
    if (parent_signal) {
        siginfo_t info = {
            .si_signo = parent_signal,
            .si_pid = child_pid,
            .si_uid = uid,
            /* These 2 fields are not supported in Graphene. */
            .si_utime = 0,
            .si_stime = 0,
        };
        fill_siginfo_code_and_status(&info, signal, exit_code);
        int x = kill_current_proc(&info);
        if (x < 0) {
            debug("Sending child death signal failed: %d!\n", x);
        }
    }

    unlock(&g_process.children_lock);

    while (wait_queue) {
        struct shim_thread_queue* next = wait_queue->next;
        struct shim_thread* thread = wait_queue->thread;
        __atomic_store_n(&wait_queue->in_use, false, __ATOMIC_RELEASE);
        COMPILER_BARRIER();
        thread_wakeup(thread);
        wait_queue = next;
    }

    return ret;
}

bool mark_child_exited_by_vmid(IDTYPE vmid, IDTYPE uid, int exit_code, int signal) {
    return mark_child_exited(cmp_child_by_vmid, (unsigned long)vmid, uid, exit_code, signal);
}

bool mark_child_exited_by_pid(IDTYPE pid, IDTYPE uid, int exit_code, int signal) {
    return mark_child_exited(cmp_child_by_pid, (unsigned long)pid, uid, exit_code, signal);
}

BEGIN_CP_FUNC(process_description) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct shim_process));

    struct shim_process* process = (struct shim_process*)obj;

    size_t children_count = 0;
    size_t zombies_count = 0;
    struct shim_child_process* child = NULL;
    LISTP_FOR_EACH_ENTRY(child, &process->children, list) {
        ++children_count;
    }
    struct shim_child_process* zombie = NULL;
    LISTP_FOR_EACH_ENTRY(zombie, &process->zombies, list) {
        ++zombies_count;
    }

    size_t off = ADD_CP_OFFSET(sizeof(struct shim_process) + sizeof(children_count)
                               + children_count * sizeof(struct shim_child_process)
                               + sizeof(zombies_count)
                               + zombies_count * sizeof(struct shim_child_process));
    struct shim_process* new_process = (struct shim_process*)(base + off);

    memset(new_process, '\0', sizeof(*new_process));

    new_process->pid = process->pid;
    new_process->ppid = process->ppid;
    new_process->pgid = process->pgid;

    DO_CP_MEMBER(dentry, process, new_process, root);
    DO_CP_MEMBER(dentry, process, new_process, cwd);
    new_process->umask = process->umask;

    DO_CP_MEMBER(handle, process, new_process, exec);

    INIT_LISTP(&new_process->children);
    INIT_LISTP(&new_process->zombies);

    clear_lock(&new_process->fs_lock);
    clear_lock(&new_process->children_lock);

    *(size_t*)((char*)new_process + sizeof(*new_process)) = children_count;
    struct shim_child_process* children =
        (struct shim_child_process*)((char*)new_process + sizeof(*new_process)
                                     + sizeof(children_count));
    size_t i = 0;
    LISTP_FOR_EACH_ENTRY(child, &process->children, list) {
        memcpy(&children[i], child, sizeof(children[i]));
        INIT_LIST_HEAD(&children[i], list);
        i++;
    }

    assert(i == children_count);

    *(size_t*)((char*)children + children_count * sizeof(*children)) = zombies_count;
    struct shim_child_process* zombies =
        (struct shim_child_process*)((char*)children + children_count * sizeof(*children)
                                     + sizeof(zombies_count));
    i = 0;
    LISTP_FOR_EACH_ENTRY(zombie, &process->zombies, list) {
        memcpy(&zombies[i], zombie, sizeof(zombies[i]));
        INIT_LIST_HEAD(&zombies[i], list);
        i++;
    }

    assert(i == zombies_count);

    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(process_description)

BEGIN_RS_FUNC(process_description) {
    struct shim_process* process = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(process->root);
    CP_REBASE(process->cwd);
    CP_REBASE(process->exec);

    if (process->exec) {
        get_handle(process->exec);
    }
    if (process->root) {
        get_dentry(process->root);
    }
    if (process->cwd) {
        get_dentry(process->cwd);
    }

    if (!create_lock(&process->fs_lock)) {
        return -ENOMEM;
    }
    if (!create_lock(&process->children_lock)) {
        destroy_lock(&process->fs_lock);
        return -ENOMEM;
    }

    /* We never checkpoint any thread wait queues, since after clone/execve there is only one thread
     * and by definition it is not waiting. */
    process->wait_queue = NULL;

    INIT_LISTP(&process->children);
    INIT_LISTP(&process->zombies);

    size_t children_count = *(size_t*)((char*)process + sizeof(*process));
    struct shim_child_process* children =
        (struct shim_child_process*)((char*)process + sizeof(*process) + sizeof(children_count));
    for (size_t i = 0; i < children_count; i++) {
        LISTP_ADD_TAIL(&children[i], &process->children, list);
    }

    size_t zombies_count = *(size_t*)((char*)children + children_count * sizeof(*children));
    struct shim_child_process* zombies =
        (struct shim_child_process*)((char*)children + children_count * sizeof(*children)
                                     + sizeof(zombies_count));
    for (size_t i = 0; i < zombies_count; i++) {
        LISTP_ADD_TAIL(&zombies[i], &process->zombies, list);
    }

    memcpy(&g_process, process, sizeof(g_process));
#ifdef DEBUG
    memset(process, '\xcc', sizeof(*process));
#endif
}
END_RS_FUNC(process_description)
