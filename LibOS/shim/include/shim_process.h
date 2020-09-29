/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#ifndef _SHIM_PROCESS_H
#define _SHIM_PROCESS_H

#include <stdbool.h>

#include "list.h"
#include "pal.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_lock.h"
#include "shim_types.h"

DEFINE_LIST(shim_child_process);
DEFINE_LISTP(shim_child_process);
struct shim_child_process {
    IDTYPE pid;
    IDTYPE vmid;

    int death_notification_signal;

    int exit_code;
    int term_signal;
    IDTYPE uid;

    LIST_TYPE(shim_child_process) list;
};

struct shim_process {
    /* These 2 fields are constant and can safely be read without any locks held. */
    IDTYPE pid;
    IDTYPE ppid;

    /* This field should be accessed atomically, so no lock needed. */
    IDTYPE pgid;

    /* Currently all threads share filesystem information. For more info check `CLONE_FS` flag in
     * `clone.c`. Protected by `fs_lock`. */
    struct shim_dentry* root;
    struct shim_dentry* cwd;
    mode_t umask;

    /* Handle to the executable. Protected by `fs_lock`. */
    struct shim_handle* exec;

    /* Threads waiting for some child to exit. Protected by `children_lock`. */
    struct shim_thread_queue* wait_queue;

    /* List of child processes that are still running. Protected by `children_lock`. */
    LISTP_TYPE(shim_child_process) children;
    /* List of already exited children. Protected by `children_lock`. */
    LISTP_TYPE(shim_child_process) zombies;

    struct shim_lock children_lock;
    struct shim_lock fs_lock;
};

extern struct shim_process g_process;

int init_process(void);

/* Allocates a new child process structure, initializing all fields. */
struct shim_child_process* create_child_process(void);
/* Frees `child` with all acompanying resources. */
void destroy_child_process(struct shim_child_process* child);
/* Adds `child` to `g_process` children list. */
void add_child_process(struct shim_child_process* child);

/*
 * These 2 functions mark a child as exited, moving it from `children` list to `zombies` list
 * and generate a child-death signal (if needed).
 * Return `true` if the child was found, `false` otherwise.
 */
bool mark_child_exited_by_vmid(IDTYPE vmid, IDTYPE uid, int exit_code, int signal);
bool mark_child_exited_by_pid(IDTYPE pid, IDTYPE uid, int exit_code, int signal);

#endif // _SHIM_PROCESS_H
