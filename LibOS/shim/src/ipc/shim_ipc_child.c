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
 * shim_ipc_child.c
 *
 * This file contains functions and callbacks to handle IPC between parent
 * processes and their children.
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_thread.h>
#include <shim_utils.h>

struct thread_info {
    IDTYPE vmid;
    unsigned int exitcode;
    unsigned int term_signal;
};

/* walk_simple_thread_list callback; exit each simple thread of child process vmid. */
static int child_sthread_exit(struct shim_simple_thread* thread, void* arg, bool* unlocked) {
    __UNUSED(unlocked); /* FYI: notifies about unlocked thread_list_lock */

    struct thread_info* info = (struct thread_info*)arg;
    int found_exiting_thread = 0;

    lock(&thread->lock);
    if (thread->vmid == info->vmid) {
        found_exiting_thread = 1;

        if (thread->is_alive) {
            thread->exit_code   = -info->exitcode;
            thread->term_signal = info->term_signal;
            thread->is_alive    = false;

            /* arrange exit event for subsequent wait4(thread->tid) */
            DkEventSet(thread->exit_event);
        }
    }
    unlock(&thread->lock);
    return found_exiting_thread;
}

/* walk_thread_list callback; exit each thread of child process vmid. */
static int child_thread_exit(struct shim_thread* thread, void* arg, bool* unlocked) {
    __UNUSED(unlocked); /* FYI: notifies about unlocked thread_list_lock */

    struct thread_info* info = (struct thread_info*)arg;
    int found_exiting_thread = 0;

    lock(&thread->lock);
    if (thread->vmid == info->vmid) {
        found_exiting_thread = 1;

        if (thread->is_alive) {
            thread->exit_code   = -info->exitcode;
            thread->term_signal = info->term_signal;
            unlock(&thread->lock);

            /* remote thread is "virtually" exited: SIGCHLD is generated for
             * the parent thread and exit events are arranged for subsequent
             * wait4(). */
            thread_exit(thread, /*send_ipc=*/false);
            goto out;
        }
    }
    unlock(&thread->lock);

out:
    return found_exiting_thread;
}

/* IPC helper thread invokes this fini function when main IPC port for
 * communication with child process is disconnected/removed by host OS.
 *
 * Similarly to benign case of receiving an explicit IPC_CLD_EXIT message
 * from exiting remote thread (see ipc_cld_exit_callback()), we want to
 * delete all remote threads associated with disconnected child process.
 */
void ipc_port_with_child_fini(struct shim_ipc_port* port, IDTYPE vmid, unsigned int exitcode) {
    __UNUSED(port);

    /* NOTE: IPC port may be closed by host OS because the child process
     *       exited on host OS (and so host OS closed all its sockets).
     *       This may happen before arrival of the "expected" IPC_CLD_EXIT
     *       message from child process. Ideally, we would inspect whether
     *       we previously sent SIGINT/SIGTERM/SIGKILL to this child and
     *       use the corresponding termination signal. For now, we simply
     *       report that child process was killed by SIGKILL. */
    struct thread_info info = {.vmid = vmid, .exitcode = exitcode, .term_signal = SIGKILL};

    /* message cannot come from our own threads (from ourselves as process) */
    assert(vmid != cur_process.vmid);

    int ret;
    int exited_threads_cnt = 0;

    if ((ret = walk_thread_list(&child_thread_exit, &info)) > 0)
        exited_threads_cnt += ret;
    if ((ret = walk_simple_thread_list(&child_sthread_exit, &info)) > 0)
        exited_threads_cnt += ret;

    debug(
        "Child process %u got disconnected: assuming that child exited and "
        "forcing %d of its threads to exit\n",
        vmid & 0xFFFF, exited_threads_cnt);
}

DEFINE_PROFILE_INTERVAL(ipc_cld_exit_turnaround, ipc);
DEFINE_PROFILE_INTERVAL(ipc_cld_exit_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_cld_exit_callback, ipc);

/* The exiting thread of this process calls this function to broadcast
 * IPC_CLD_EXIT notification to its parent process (technically, to all
 * processes of type DIRPRT or DIRCLD but the only interesting case is
 * the notification of parent). */
int ipc_cld_exit_send(IDTYPE ppid, IDTYPE tid, unsigned int exitcode, unsigned int term_signal) {
    __attribute__((unused)) unsigned long send_time = GET_PROFILE_INTERVAL();
    BEGIN_PROFILE_INTERVAL_SET(send_time);

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_cld_exit));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_CLD_EXIT, total_msg_size, 0);

    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;
    msgin->ppid                     = ppid;
    msgin->tid                      = tid;
    msgin->exitcode                 = exitcode;
    msgin->term_signal              = term_signal;
#ifdef PROFILE
    msgin->time = send_time;
#endif

    debug("IPC broadcast: IPC_CLD_EXIT(%u, %u, %d, %u)\n", ppid, tid, exitcode, term_signal);

    int ret = broadcast_ipc(msg, IPC_PORT_DIRPRT | IPC_PORT_DIRCLD,
                            /*exclude_port=*/NULL);
    SAVE_PROFILE_INTERVAL(ipc_cld_exit_send);
    return ret;
}

/* IPC helper thread invokes this callback on an IPC_CLD_EXIT message received
 * from a specific thread msgin->tid of the exiting child process with vmid
 * msg->src. The thread of the exiting child process informs about its exit
 * code in msgin->exit_code and its terminating signal in msgin->term_signal.
 *
 * The callback finds this remote thread of the child process among our
 * process's threads/simple threads (recall that parent process maintains
 * remote child threads in its thread list, marking them as in_vm == false).
 * The remote thread is "virtually" exited: SIGCHLD is generated for the
 * parent thread and exit events are arranged for subsequent wait4().
 */
int ipc_cld_exit_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    __UNUSED(port);
    int ret = 0;

    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;

#ifdef PROFILE
    unsigned long time = msgin->time;
    if (!time)
        time = GET_PROFILE_INTERVAL();
#endif
    BEGIN_PROFILE_INTERVAL_SET(time);
    SAVE_PROFILE_INTERVAL(ipc_cld_exit_turnaround);

    debug("IPC callback from %u: IPC_CLD_EXIT(%u, %u, %d, %u)\n", msg->src & 0xFFFF, msgin->ppid,
          msgin->tid, msgin->exitcode, msgin->term_signal);

    /* message cannot come from our own threads (from ourselves as process) */
    assert(msg->src != cur_process.vmid);

    /* First try to find remote thread which sent this message among normal
     * threads. In the common case, we (as parent process) keep remote child
     * threads in the thread list. But sometimes the message can arrive twice
     * or very late, such that the corresponding remote thread was already
     * exited and deleted; in such cases, we fall back to simple threads. */
    struct shim_thread* thread = lookup_thread(msgin->tid);
    if (thread) {
        lock(&thread->lock);
        thread->exit_code   = -msgin->exitcode;
        thread->term_signal = msgin->term_signal;
#ifdef PROFILE
        thread->exit_time = time;
#endif
        unlock(&thread->lock);

        /* Remote thread is "virtually" exited: SIGCHLD is generated for the
         * parent thread and exit events are arranged for subsequent wait4(). */
        ret = thread_exit(thread, /*send_ipc=*/false);
        put_thread(thread);
    } else {
        /* Uncommon case: remote child thread was already exited and deleted
         * (probably because the same message was already received earlier).
         * Find or create a simple thread for a sole purpose of arranging
         * exit events for subsequent wait4(). */
        struct shim_simple_thread* sthread = lookup_simple_thread(msgin->tid);

        if (!sthread) {
            sthread       = get_new_simple_thread();
            sthread->vmid = msg->src;
            sthread->tid  = msgin->tid;
            add_simple_thread(sthread);
        }

        lock(&sthread->lock);
        sthread->is_alive    = false;
        sthread->exit_code   = -msgin->exitcode;
        sthread->term_signal = msgin->term_signal;
#ifdef PROFILE
        sthread->exit_time = time;
#endif
        unlock(&sthread->lock);

        DkEventSet(sthread->exit_event); /* for wait4(msgin->tid) */
        put_simple_thread(sthread);
    }

    SAVE_PROFILE_INTERVAL(ipc_cld_exit_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_send_profile, ipc);

#ifdef PROFILE
int ipc_cld_profile_send(void) {
    struct shim_ipc_port* port = NULL;
    IDTYPE dest                = (IDTYPE)-1;

    /* port and dest are initialized to parent process */
    lock(&cur_process.lock);
    if (cur_process.parent && (port = cur_process.parent->port)) {
        get_ipc_port(port);
        dest = cur_process.parent->vmid;
    }
    unlock(&cur_process.lock);

    if (!port || (dest == (IDTYPE)-1))
        return -ESRCH;

    unsigned long time = GET_PROFILE_INTERVAL();
    size_t nsending    = 0;
    for (size_t i = 0; i < N_PROFILE; i++) {
        switch (PROFILES[i].type) {
            case OCCURENCE:
                if (atomic_read(&PROFILES[i].val.occurence.count))
                    nsending++;
                break;
            case INTERVAL:
                if (atomic_read(&PROFILES[i].val.interval.count))
                    nsending++;
                break;
            case CATEGORY:
                break;
        }
    }

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_cld_profile) +
                                             sizeof(struct profile_val) * nsending);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_CLD_PROFILE, total_msg_size, dest);

    struct shim_ipc_cld_profile* msgin = (struct shim_ipc_cld_profile*)&msg->msg;

    size_t nsent = 0;
    for (size_t i = 0; i < N_PROFILE && nsent < nsending; i++) {
        switch (PROFILES[i].type) {
            case OCCURENCE: {
                unsigned long count = atomic_read(&PROFILES[i].val.occurence.count);
                if (count) {
                    msgin->profile[nsent].idx                 = i + 1;
                    msgin->profile[nsent].val.occurence.count = count;
                    debug("Send %s: %lu times\n", PROFILES[i].name, count);
                    nsent++;
                }
                break;
            }
            case INTERVAL: {
                unsigned long count = atomic_read(&PROFILES[i].val.interval.count);
                if (count) {
                    msgin->profile[nsent].idx                = i + 1;
                    msgin->profile[nsent].val.interval.count = count;
                    msgin->profile[nsent].val.interval.time =
                        atomic_read(&PROFILES[i].val.interval.time);
                    debug("Send %s: %lu times, %lu msec\n", PROFILES[i].name, count,
                          msgin->profile[nsent].val.interval.time);
                    nsent++;
                }
                break;
            }
            case CATEGORY:
                break;
        }
    }

    msgin->time     = time;
    msgin->nprofile = nsent;

    debug("IPC send to %u: IPC_CLD_PROFILE\n", dest & 0xFFFF);
    int ret = send_ipc_message(msg, port);

    put_ipc_port(port);
    return ret;
}

int ipc_cld_profile_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    debug("IPC callback from %u: IPC_CLD_PROFILE\n", msg->src & 0xFFFF);

    struct shim_ipc_cld_profile* msgin = (struct shim_ipc_cld_profile*)&msg->msg;

    for (int i = 0; i < msgin->nprofile; i++) {
        int idx = msgin->profile[i].idx;
        if (idx == 0)
            break;
        idx--;
        switch (PROFILES[idx].type) {
            case OCCURENCE:
                debug("Receive %s: %u times\n", PROFILES[idx].name,
                      msgin->profile[i].val.occurence.count);
                atomic_add(msgin->profile[i].val.occurence.count,
                           &PROFILES[idx].val.occurence.count);
                break;
            case INTERVAL:
                debug("Receive %s: %u times, %lu msec\n", PROFILES[idx].name,
                      msgin->profile[i].val.interval.count, msgin->profile[i].val.interval.time);
                atomic_add(msgin->profile[i].val.interval.count, &PROFILES[idx].val.interval.count);
                atomic_add(msgin->profile[i].val.interval.time, &PROFILES[idx].val.interval.time);
                break;
            case CATEGORY:
                break;
        }
    }

    SAVE_PROFILE_INTERVAL_SINCE(ipc_send_profile, msgin->time);
    return 0;
}
#endif
