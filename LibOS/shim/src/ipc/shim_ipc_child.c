/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * shim_ipc_helper.c
 *
 * This file contains functions and callbacks to handle IPC between parent
 * processes and their children.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_ipc.h>
#include <shim_utils.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

static int ipc_thread_exit (IDTYPE vmid, IDTYPE ppid, IDTYPE tid,
                            unsigned int exitcode, unsigned int term_signal, unsigned long exit_time)
{
    assert(vmid != cur_process.vmid);

#ifdef PROFILE
    if (!exit_time)
        exit_time = GET_PROFILE_INTERVAL();
#endif

    struct shim_thread * thread = __lookup_thread(tid);

    if (thread) {
        int ret = 0;
        //assert(thread->vmid == vmid && !thread->in_vm);
        thread->exit_code = -exitcode;
        thread->term_signal = term_signal;
#ifdef PROFILE
        thread->exit_time = exit_time;
#endif
        ret = thread_exit(thread, false);
        put_thread(thread);
        return ret;
    }

    struct shim_simple_thread * sthread = __lookup_simple_thread(tid);

    if (!sthread) {
        sthread = get_new_simple_thread();
        sthread->vmid = vmid;
        sthread->tid = tid;
        add_simple_thread(sthread);
    }

    sthread->is_alive = 0;
    sthread->exit_code = -exitcode;
    sthread->term_signal = term_signal;
#ifdef PROFILE
    sthread->exit_time = exit_time;
#endif
    DkEventSet(sthread->exit_event);
    put_simple_thread(sthread);
    return 0;
}

void ipc_parent_exit (struct shim_ipc_port * port, IDTYPE vmid,
                      unsigned int exitcode)
{
    debug("ipc port %p of process %u closed suggests parent exiting\n",
          port, vmid);

    struct shim_ipc_info * parent = NULL;

    lock(cur_process.lock);

    if (parent && vmid == cur_process.parent->vmid) {
        parent = cur_process.parent;
        cur_process.parent = NULL;
    }

    unlock(cur_process.lock);

    if (parent)
        put_ipc_info(parent);
}

struct thread_info {
    IDTYPE vmid;
    unsigned int exitcode;
    unsigned int term_signal;
};

static int child_sthread_exit (struct shim_simple_thread * thread, void * arg,
                               bool * unlocked)
{
    struct thread_info * info = (struct thread_info *) arg;
    if (thread->vmid == info->vmid) {
        if (thread->is_alive) {
            thread->exit_code = -info->exitcode;
            thread->term_signal = info->term_signal;
            thread->is_alive = false;
            DkEventSet(thread->exit_event);
        }
        return 1;
    }
    return 0;
}

static int child_thread_exit (struct shim_thread * thread, void * arg,
                              bool * unlocked)
{
    struct thread_info * info = (struct thread_info *) arg;
    if (thread->vmid == info->vmid) {
        if (thread->is_alive) {
            thread->exit_code = -info->exitcode;
            thread->term_signal = info->term_signal;
            thread_exit(thread, false);
        }
        return 1;
    }
    return 0;
}

int remove_child_thread (IDTYPE vmid, unsigned int exitcode, unsigned int term_signal)
{
    struct thread_info info = { .vmid = vmid, .exitcode = exitcode, .term_signal = term_signal };
    int nkilled = 0, ret;

    assert(vmid != cur_process.vmid);

    if ((ret = walk_thread_list(&child_thread_exit, &info, false)) > 0)
        nkilled += ret;

    if ((ret = walk_simple_thread_list(&child_sthread_exit, &info, false)) > 0)
        nkilled += ret;

    if (!nkilled)
        debug("child port closed, no thread exited\n");

    return 0;
}

void ipc_child_exit (struct shim_ipc_port * port, IDTYPE vmid,
                     unsigned int exitcode)
{
    debug("ipc port %p of process %u closed suggests child exiting\n",
          port, vmid);

    /*
     * Chia-Che 12/12/2017:
     * Can't assume there is a termination signal. this callback
     * is only called when the child process is not responding, and
     * under this circumstance can only assume the child process
     * has encountered severe failure, hence SIGKILL.
     */
    remove_child_thread(vmid, exitcode, SIGKILL);
}

static struct shim_ipc_port * get_parent_port (IDTYPE * dest)
{
    struct shim_ipc_port * port = NULL;
    lock(cur_process.lock);
    if (cur_process.parent && (port = cur_process.parent->port)) {
        get_ipc_port(port);
        *dest = cur_process.parent->vmid;
    }
    unlock(cur_process.lock);
    return port;
}

DEFINE_PROFILE_INTERVAL(ipc_cld_exit_turnaround, ipc);
DEFINE_PROFILE_INTERVAL(ipc_cld_exit_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_cld_exit_callback, ipc);

int ipc_cld_exit_send (IDTYPE ppid, IDTYPE tid, unsigned int exitcode, unsigned int term_signal)
{
    __attribute__((unused)) unsigned long send_time = GET_PROFILE_INTERVAL();
    BEGIN_PROFILE_INTERVAL_SET(send_time);
    int ret = 0;

    struct shim_ipc_msg * msg =
            create_ipc_msg_on_stack(IPC_CLD_EXIT,
                                    sizeof(struct shim_ipc_cld_exit), 0);
    struct shim_ipc_cld_exit * msgin =
                (struct shim_ipc_cld_exit *) &msg->msg;
    msgin->ppid = ppid;
    msgin->tid = tid;
    msgin->exitcode = exitcode;
    msgin->term_signal = term_signal;
#ifdef PROFILE
    msgin->time = send_time;
#endif

    debug("ipc broadcast: IPC_CLD_EXIT(%u, %u, %d)\n", ppid, tid, exitcode);

    ret = broadcast_ipc(msg, NULL, 0, IPC_PORT_DIRPRT|IPC_PORT_DIRCLD);
    SAVE_PROFILE_INTERVAL(ipc_cld_exit_send);
    return ret;
}

int ipc_cld_exit_callback (IPC_CALLBACK_ARGS)
{
    struct shim_ipc_cld_exit * msgin =
                (struct shim_ipc_cld_exit *) &msg->msg;

#ifdef PROFILE
    unsigned long time = msgin->time;
#else
    unsigned long time = 0;
#endif
    BEGIN_PROFILE_INTERVAL_SET(time);
    SAVE_PROFILE_INTERVAL(ipc_cld_exit_turnaround);

    debug("ipc callback from %u: IPC_CLD_EXIT(%u, %u, %d)\n",
          msg->src, msgin->ppid, msgin->tid, msgin->exitcode);

    int ret = ipc_thread_exit(msg->src, msgin->ppid, msgin->tid,
                              msgin->exitcode, msgin->term_signal,
                              time);
    SAVE_PROFILE_INTERVAL(ipc_cld_exit_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_cld_join_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_cld_join_callback, ipc);

int ipc_cld_join_send (IDTYPE dest)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_port * port = dest ?
                                  lookup_ipc_port(dest, IPC_PORT_DIRPRT) :
                                  get_parent_port(&dest);
    if (!port)
        return -ESRCH;

    struct shim_ipc_msg * msg =
                create_ipc_msg_on_stack(IPC_CLD_JOIN, 0, dest);

    debug("ipc send to %u: IPC_CLD_JOIN\n", dest);

    int ret = send_ipc_message(msg, port);

    add_ipc_port(port, dest, IPC_PORT_DIRPRT, NULL);
    put_ipc_port(port);
    SAVE_PROFILE_INTERVAL(ipc_cld_join_send);
    return ret;
}

int ipc_cld_join_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    debug("ipc callback from %u: IPC_CLD_JOIN\n", msg->src);
    add_ipc_port(port, msg->src, IPC_PORT_DIRCLD, NULL);
    SAVE_PROFILE_INTERVAL(ipc_cld_join_callback);
    return 0;
}

DEFINE_PROFILE_INTERVAL(ipc_send_profile, ipc);

#ifdef PROFILE
int ipc_cld_profile_send (void)
{
    IDTYPE dest;
    struct shim_ipc_port * port = get_parent_port(&dest);
    if (!port)
        return -ESRCH;

    unsigned long time = GET_PROFILE_INTERVAL();
    int nsending = 0;
    for (int i = 0 ; i < N_PROFILE ; i++)
        switch (PROFILES[i].type) {
            case OCCURENCE:
                if (atomic_read(&PROFILES[i].val.occurence.count))
                    nsending++;
                break;
            case INTERVAL:
                if (atomic_read(&PROFILES[i].val.interval.count))
                    nsending++;
                break;
            case CATAGORY:
                break;
        }


    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_CLD_PROFILE,
                                        sizeof(struct shim_ipc_cld_profile) +
                                        sizeof(struct profile_val) *
                                        nsending, dest);
    struct shim_ipc_cld_profile * msgin =
                (struct shim_ipc_cld_profile *) &msg->msg;

    int nsent = 0;
    for (int i = 0 ; i < N_PROFILE && nsent < nsending ; i++)
        switch (PROFILES[i].type) {
            case OCCURENCE: {
                unsigned long count =
                    atomic_read(&PROFILES[i].val.occurence.count);
                if (count) {
                    msgin->profile[nsent].idx = i + 1;
                    msgin->profile[nsent].val.occurence.count = count;
                    debug("send %s: %lu times\n", PROFILES[i].name, count);
                    nsent++;
                }
                break;
            }
            case INTERVAL: {
                unsigned long count =
                    atomic_read(&PROFILES[i].val.interval.count);
                if (count) {
                    msgin->profile[nsent].idx = i + 1;
                    msgin->profile[nsent].val.interval.count = count;
                    msgin->profile[nsent].val.interval.time =
                        atomic_read(&PROFILES[i].val.interval.time);
                    debug("send %s: %lu times, %lu msec\n", PROFILES[i].name,
                          count, msgin->profile[nsent].val.interval.time);
                    nsent++;
                }
                break;
            }
            case CATAGORY:
                break;
        }

    msgin->time = time;
    msgin->nprofile = nsent;

    debug("ipc send to %u: IPC_CLD_PROFILE\n", dest);

    int ret = send_ipc_message(msg, port);
    put_ipc_port(port);
    return ret;
}

int ipc_cld_profile_callback (IPC_CALLBACK_ARGS)
{
    struct shim_ipc_cld_profile * msgin =
                (struct shim_ipc_cld_profile *) &msg->msg;

    debug("ipc callback from %u: IPC_CLD_PROFILE\n", msg->src);

    for (int i = 0 ; i < msgin->nprofile ; i++) {
        int idx = msgin->profile[i].idx;
        if (idx == 0)
            break;
        idx--;
        switch (PROFILES[idx].type) {
            case OCCURENCE:
                debug("receive %s: %u times\n", PROFILES[idx].name,
                      msgin->profile[i].val.occurence.count);
                atomic_add(msgin->profile[i].val.occurence.count,
                           &PROFILES[idx].val.occurence.count);
                break;
            case INTERVAL:
                debug("receive %s: %u times, %lu msec\n", PROFILES[idx].name,
                      msgin->profile[i].val.interval.count,
                      msgin->profile[i].val.interval.time);
                atomic_add(msgin->profile[i].val.interval.count,
                           &PROFILES[idx].val.interval.count);
                atomic_add(msgin->profile[i].val.interval.time,
                           &PROFILES[idx].val.interval.time);
                break;
            case CATAGORY:
                break;
        }
    }

    SAVE_PROFILE_INTERVAL_SINCE(ipc_send_profile, msgin->time);
    return 0;
}
#endif
