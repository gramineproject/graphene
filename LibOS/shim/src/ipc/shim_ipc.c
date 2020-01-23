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
 * shim_ipc.c
 *
 * This file contains code to maintain generic bookkeeping of IPC: operations
 * on shim_ipc_msg (one-way IPC messages), shim_ipc_msg_duplex (IPC messages
 * with acknowledgement), shim_ipc_info (IPC ports of process), shim_process.
 */

#include <list.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_thread.h>
#include <shim_unistd.h>
#include <shim_utils.h>

static struct shim_lock ipc_info_mgr_lock;

#define SYSTEM_LOCK()   lock(&ipc_info_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&ipc_info_mgr_lock)
#define SYSTEM_LOCKED() locked(&ipc_info_mgr_lock)

#define IPC_INFO_MGR_ALLOC 32
#define OBJ_TYPE           struct shim_ipc_info
#include "memmgr.h"
static MEM_MGR ipc_info_mgr;

struct shim_lock ipc_info_lock;

struct shim_process cur_process;

#define CLIENT_HASH_BITLEN 6
#define CLIENT_HASH_NUM    (1 << CLIENT_HASH_BITLEN)
#define CLIENT_HASH_MASK   (CLIENT_HASH_NUM - 1)
#define CLIENT_HASH(vmid)  ((vmid)&CLIENT_HASH_MASK)
DEFINE_LISTP(shim_ipc_info);
static LISTP_TYPE(shim_ipc_info) info_hlist[CLIENT_HASH_NUM];

DEFINE_PROFILE_CATEGORY(ipc, );
DEFINE_PROFILE_OCCURENCE(syscall_use_ipc, ipc);

int init_ipc_ports(void);
int init_ns_pid(void);
int init_ns_sysv(void);

int init_ipc(void) {
    int ret = 0;

    if (!create_lock(&ipc_info_lock)
        || !create_lock(&cur_process.lock)
        || !create_lock(&ipc_info_mgr_lock)) {
        return -ENOMEM;
    }

    if (!(ipc_info_mgr = create_mem_mgr(init_align_up(IPC_INFO_MGR_ALLOC))))
        return -ENOMEM;

    if ((ret = init_ipc_ports()) < 0)
        return ret;
    if ((ret = init_ns_pid()) < 0)
        return ret;
    if ((ret = init_ns_sysv()) < 0)
        return ret;

    return 0;
}

int prepare_ns_leaders(void) {
    int ret = 0;
    if ((ret = prepare_pid_leader()) < 0)
        return ret;
    if ((ret = prepare_sysv_leader()) < 0)
        return ret;
    return 0;
}

static struct shim_ipc_info* __create_ipc_info(IDTYPE vmid, const char* uri, size_t len) {
    assert(locked(&ipc_info_lock));

    struct shim_ipc_info* info =
        get_mem_obj_from_mgr_enlarge(ipc_info_mgr, size_align_up(IPC_INFO_MGR_ALLOC));
    if (!info)
        return NULL;

    memset(info, 0, sizeof(struct shim_ipc_info));
    info->vmid = vmid;
    if (uri)
        qstrsetstr(&info->uri, uri, len);
    REF_SET(info->ref_count, 1);
    INIT_LIST_HEAD(info, hlist);
    return info;
}

static void __free_ipc_info(struct shim_ipc_info* info) {
    assert(locked(&ipc_info_lock));

    if (info->pal_handle) {
        DkObjectClose(info->pal_handle);
        info->pal_handle = NULL;
    }
    if (info->port)
        put_ipc_port(info->port);
    qstrfree(&info->uri);
    free_mem_obj_to_mgr(ipc_info_mgr, info);
}

static void __get_ipc_info(struct shim_ipc_info* info) {
    REF_INC(info->ref_count);
}

static void __put_ipc_info(struct shim_ipc_info* info) {
    assert(locked(&ipc_info_lock));

    int ref_count = REF_DEC(info->ref_count);
    if (!ref_count)
        __free_ipc_info(info);
}

void get_ipc_info(struct shim_ipc_info* info) {
    /* no need to grab ipc_info_lock because __get_ipc_info() does not touch global state */
    __get_ipc_info(info);
}

void put_ipc_info(struct shim_ipc_info* info) {
    /* this is atomic so we don't grab lock in common case of ref_count > 0 */
    int ref_count = REF_DEC(info->ref_count);

    if (!ref_count) {
        lock(&ipc_info_lock);
        __free_ipc_info(info);
        unlock(&ipc_info_lock);
    }
}

struct shim_ipc_info* create_ipc_info(IDTYPE vmid, const char* uri, size_t len) {
    lock(&ipc_info_lock);
    struct shim_ipc_info* info = __create_ipc_info(vmid, uri, len);
    unlock(&ipc_info_lock);
    return info;
}

struct shim_ipc_info* create_ipc_info_in_list(IDTYPE vmid, const char* uri, size_t len) {
    assert(vmid);

    struct shim_ipc_info* info;
    lock(&ipc_info_lock);

    /* check if info with this vmid & uri already exists and return it */
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(vmid)];
    LISTP_FOR_EACH_ENTRY(info, info_bucket, hlist) {
        if (info->vmid == vmid && !qstrcmpstr(&info->uri, uri, len)) {
            get_ipc_info(info);
            unlock(&ipc_info_lock);
            return info;
        }
    }

    /* otherwise create new info and return it */
    info = __create_ipc_info(vmid, uri, len);
    if (info) {
        LISTP_ADD(info, info_bucket, hlist);
        get_ipc_info(info);
    }

    unlock(&ipc_info_lock);
    return info;
}

void put_ipc_info_in_list(struct shim_ipc_info* info) {
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(info->vmid)];

    lock(&ipc_info_lock);
    __put_ipc_info(info);
    if (REF_GET(info->ref_count) == 1) {
        LISTP_DEL_INIT(info, info_bucket, hlist);
        __put_ipc_info(info);
    }
    unlock(&ipc_info_lock);
}

struct shim_ipc_info* lookup_ipc_info(IDTYPE vmid) {
    assert(vmid);
    lock(&ipc_info_lock);

    struct shim_ipc_info* info;
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(vmid)];
    LISTP_FOR_EACH_ENTRY(info, info_bucket, hlist) {
        if (info->vmid == vmid && !qstrempty(&info->uri)) {
            __get_ipc_info(info);
            unlock(&ipc_info_lock);
            return info;
        }
    }

    unlock(&ipc_info_lock);
    return NULL;
}

struct shim_process* create_process(bool dup_cur_process) {
    struct shim_process* new_process = calloc(1, sizeof(struct shim_process));
    if (!new_process)
        return NULL;

    lock(&cur_process.lock);

    /* current process must have been initialized with info on its own IPC info */
    assert(cur_process.self);
    assert(cur_process.self->pal_handle && !qstrempty(&cur_process.self->uri));

    if (dup_cur_process) {
        /* execve case, new process assumes identity of current process and thus has
         * - same vmid as current process
         * - same self IPC info as current process
         * - same parent IPC info as current process
         */
        new_process->vmid = cur_process.vmid;

        new_process->self = create_ipc_info(
            cur_process.self->vmid, qstrgetstr(&cur_process.self->uri), cur_process.self->uri.len);
        new_process->self->pal_handle = cur_process.self->pal_handle;
        if (!new_process->self) {
            unlock(&cur_process.lock);
            return NULL;
        }

        /* there is a corner case of execve in very first process; such process does
         * not have parent process, so cannot copy parent IPC info */
        if (cur_process.parent) {
            new_process->parent =
                create_ipc_info(cur_process.parent->vmid, qstrgetstr(&cur_process.parent->uri),
                                cur_process.parent->uri.len);
            new_process->parent->pal_handle = cur_process.parent->pal_handle;
        }
    } else {
        /* fork/clone case, new process has new identity but inherits parent  */
        new_process->vmid   = 0;
        new_process->self   = NULL;
        new_process->parent = create_ipc_info(
            cur_process.self->vmid, qstrgetstr(&cur_process.self->uri), cur_process.self->uri.len);
    }

    if (cur_process.parent && !new_process->parent) {
        if (new_process->self)
            put_ipc_info(new_process->self);
        unlock(&cur_process.lock);
        return NULL;
    }

    /* new process inherits the same namespace leaders */
    for (int i = 0; i < TOTAL_NS; i++) {
        if (cur_process.ns[i]) {
            new_process->ns[i] =
                create_ipc_info(cur_process.ns[i]->vmid, qstrgetstr(&cur_process.ns[i]->uri),
                                cur_process.ns[i]->uri.len);
            if (!new_process->ns[i]) {
                if (new_process->self)
                    put_ipc_info(new_process->self);
                if (new_process->parent)
                    put_ipc_info(new_process->parent);
                for (int j = 0; j < i; j++) {
                    put_ipc_info(new_process->ns[j]);
                }
                unlock(&cur_process.lock);
                return NULL;
            }
        }
    }

    unlock(&cur_process.lock);
    return new_process;
}

void free_process(struct shim_process* process) {
    if (process->self)
        put_ipc_info(process->self);
    if (process->parent)
        put_ipc_info(process->parent);
    for (int i = 0; i < TOTAL_NS; i++)
        if (process->ns[i])
            put_ipc_info(process->ns[i]);
    free(process);
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size, IDTYPE dest) {
    msg->code = code;
    msg->size = get_ipc_msg_size(size);
    msg->src  = cur_process.vmid;
    msg->dst  = dest;
    msg->seq  = 0;
}

void init_ipc_msg_duplex(struct shim_ipc_msg_duplex* msg, int code, size_t size, IDTYPE dest) {
    init_ipc_msg(&msg->msg, code, size, dest);
    msg->thread = NULL;
    INIT_LIST_HEAD(msg, list);
    msg->retval  = 0;
    msg->private = NULL;
}

int send_ipc_message(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    assert(msg->size >= IPC_MSG_MINIMAL_SIZE);

    msg->src = cur_process.vmid;
    debug("Sending ipc message to port %p (handle %p)\n", port, port->pal_handle);

    size_t total_bytes = msg->size;
    size_t bytes       = 0;

    do {
        PAL_NUM ret =
            DkStreamWrite(port->pal_handle, 0, total_bytes - bytes, (void*)msg + bytes, NULL);

        if (ret == PAL_STREAM_ERROR) {
            if (PAL_ERRNO == EINTR || PAL_ERRNO == EAGAIN || PAL_ERRNO == EWOULDBLOCK)
                continue;

            debug("Port %p (handle %p) was removed during sending\n", port, port->pal_handle);
            del_ipc_port_fini(port, -ECHILD);
            return -PAL_ERRNO;
        }

        bytes += ret;
    } while (bytes < total_bytes);

    return 0;
}

struct shim_ipc_msg_duplex* pop_ipc_msg_duplex(struct shim_ipc_port* port, unsigned long seq) {
    struct shim_ipc_msg_duplex* found = NULL;

    lock(&port->msgs_lock);
    struct shim_ipc_msg_duplex* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &port->msgs, list) {
        if (tmp->msg.seq == seq) {
            found = tmp;
            LISTP_DEL_INIT(tmp, &port->msgs, list);
            break;
        }
    }
    unlock(&port->msgs_lock);

    return found;
}

int send_ipc_message_duplex(struct shim_ipc_msg_duplex* msg, struct shim_ipc_port* port,
                            unsigned long* seq, void* private_data) {
    int ret = 0;

    struct shim_thread* thread = get_cur_thread();
    assert(thread);

    /* prepare thread which will send the message for waiting for response
     * (this also acquires reference to the thread) */
    if (!msg->thread)
        thread_setwait(&msg->thread, thread);

    static struct atomic_int ipc_seq_counter;
    msg->msg.seq = atomic_inc_return(&ipc_seq_counter);

    /* save the message to list of port msgs together with its private data */
    lock(&port->msgs_lock);
    msg->private = private_data;
    LISTP_ADD_TAIL(msg, &port->msgs, list);
    unlock(&port->msgs_lock);

    ret = send_ipc_message(&msg->msg, port);
    if (ret < 0)
        goto out;

    if (seq)
        *seq = msg->msg.seq;

    debug("Waiting for response (seq = %lu)\n", msg->msg.seq);

    /* force thread which will send the message to wait for response;
     * ignore unrelated interrupts but fail on actual errors */
    do {
        ret = thread_sleep(NO_TIMEOUT);
        if (ret < 0 && ret != -EINTR && ret != -EAGAIN)
            goto out;
    } while (ret != 0);

    debug("Finished waiting for response (seq = %lu, ret = %d)\n", msg->msg.seq, msg->retval);
    ret = msg->retval;
out:
    lock(&port->msgs_lock);
    if (!LIST_EMPTY(msg, list))
        LISTP_DEL_INIT(msg, &port->msgs, list);
    unlock(&port->msgs_lock);

    if (msg->thread) {
        /* put reference to the thread acquired earlier */
        put_thread(msg->thread);
        msg->thread = NULL;
    }

    return ret;
}

/* must be called with cur_process.lock taken */
struct shim_ipc_info* create_ipc_info_cur_process(bool is_self_ipc_info) {
    struct shim_ipc_info* info = create_ipc_info(cur_process.vmid, NULL, 0);
    if (!info)
        return NULL;

    /* pipe for cur_process.self is of format "pipe:<cur_process.vmid>", others with random name */
    char uri[PIPE_URI_SIZE];
    if (create_pipe(NULL, uri, PIPE_URI_SIZE, &info->pal_handle, &info->uri, is_self_ipc_info) <
        0) {
        put_ipc_info(info);
        return NULL;
    }

    add_ipc_port_by_id(cur_process.vmid, info->pal_handle, IPC_PORT_SERVER, NULL, &info->port);

    return info;
}

int get_ipc_info_cur_process(struct shim_ipc_info** info) {
    lock(&cur_process.lock);

    if (!cur_process.self) {
        cur_process.self = create_ipc_info_cur_process(true);
        if (!cur_process.self) {
            unlock(&cur_process.lock);
            return -EACCES;
        }
    }

    get_ipc_info(cur_process.self);
    *info = cur_process.self;

    unlock(&cur_process.lock);
    return 0;
}

DEFINE_PROFILE_INTERVAL(ipc_checkpoint_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_checkpoint_callback, ipc);

/* Graphene's checkpoint() syscall broadcasts a msg to all processes
 * asking to checkpoint their state and save in process-unique file in
 * directory cpdir under session cpsession. */
int ipc_checkpoint_send(const char* cpdir, IDTYPE cpsession) {
    BEGIN_PROFILE_INTERVAL();
    int ret;
    size_t len = strlen(cpdir);

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_checkpoint) + len + 1);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_CHECKPOINT, total_msg_size, 0);

    struct shim_ipc_checkpoint* msgin = (struct shim_ipc_checkpoint*)&msg->msg;
    msgin->cpsession                  = cpsession;
    memcpy(&msgin->cpdir, cpdir, len + 1);

    debug("IPC broadcast to all: IPC_CHECKPOINT(%u, %s)\n", cpsession, cpdir);

    /* broadcast to all including myself (so I can also checkpoint) */
    ret = broadcast_ipc(msg, IPC_PORT_DIRCLD | IPC_PORT_DIRPRT,
                        /*exclude_port=*/NULL);
    SAVE_PROFILE_INTERVAL(ipc_checkpoint_send);
    return ret;
}

/* This process is asked to create a checkpoint, so it:
 * - sends a Graphene-specific SIGCP signal to all its threads (for
 *   all to stop and join the checkpoint for consistent state),
 * - broadcasts checkpoint msg further to other processes. */
int ipc_checkpoint_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    BEGIN_PROFILE_INTERVAL();
    int ret                           = 0;
    struct shim_ipc_checkpoint* msgin = (struct shim_ipc_checkpoint*)msg->msg;

    debug("IPC callback from %u: IPC_CHECKPOINT(%u, %s)\n", msg->src, msgin->cpsession,
          msgin->cpdir);

    ret = create_checkpoint(msgin->cpdir, &msgin->cpsession);
    if (ret < 0)
        goto out;

    kill_all_threads(NULL, msgin->cpsession, SIGCP);
    broadcast_ipc(msg, IPC_PORT_DIRCLD | IPC_PORT_DIRPRT, port);
out:
    SAVE_PROFILE_INTERVAL(ipc_checkpoint_callback);
    return ret;
}

BEGIN_CP_FUNC(ipc_info) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_ipc_info));

    struct shim_ipc_info* info     = (struct shim_ipc_info*)obj;
    struct shim_ipc_info* new_info = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_ipc_info));
        ADD_TO_CP_MAP(obj, off);

        new_info = (struct shim_ipc_info*)(base + off);
        memcpy(new_info, info, sizeof(struct shim_ipc_info));
        REF_SET(new_info->ref_count, 0);

        /* call qstr-specific checkpointing function for new_info->uri */
        DO_CP_IN_MEMBER(qstr, new_info, uri);

        if (info->pal_handle) {
            struct shim_palhdl_entry* entry;
            /* call palhdl-specific checkpointing function to checkpoint
             * info->pal_handle and return created object in entry */
            DO_CP(palhdl, info->pal_handle, &entry);
            /* info's PAL handle will be re-opened with new URI during
             * palhdl restore (see checkpoint.c) */
            entry->uri     = &new_info->uri;
            entry->phandle = &new_info->pal_handle;
        }
    } else {
        /* already checkpointed */
        new_info = (struct shim_ipc_info*)(base + off);
    }

    if (new_info && objp)
        *objp = (void*)new_info;
}
END_CP_FUNC_NO_RS(ipc_info)

BEGIN_CP_FUNC(process) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_process));

    struct shim_process* process     = (struct shim_process*)obj;
    struct shim_process* new_process = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_process));
        ADD_TO_CP_MAP(obj, off);

        new_process = (struct shim_process*)(base + off);
        memcpy(new_process, process, sizeof(struct shim_process));

        /* call ipc_info-specific checkpointing functions
         * for new_process's self, parent, and ns infos */
        if (process->self)
            DO_CP_MEMBER(ipc_info, process, new_process, self);
        if (process->parent)
            DO_CP_MEMBER(ipc_info, process, new_process, parent);
        for (int i = 0; i < TOTAL_NS; i++)
            if (process->ns[i])
                DO_CP_MEMBER(ipc_info, process, new_process, ns[i]);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        /* already checkpointed */
        new_process = (struct shim_process*)(base + off);
    }

    if (objp)
        *objp = (void*)new_process;
}
END_CP_FUNC(process)

BEGIN_RS_FUNC(process) {
    __UNUSED(offset);
    struct shim_process* process = (void*)(base + GET_CP_FUNC_ENTRY());

    /* process vmid  = 0: fork/clone case, forces to pick up new host-OS vmid
     * process vmid != 0: execve case, forces to re-use vmid of parent */
    if (!process->vmid)
        process->vmid = cur_process.vmid;

    CP_REBASE(process->self);
    CP_REBASE(process->parent);
    CP_REBASE(process->ns);

    if (process->self) {
        process->self->vmid = process->vmid;
        get_ipc_info(process->self);
    }
    if (process->parent)
        get_ipc_info(process->parent);
    for (int i = 0; i < TOTAL_NS; i++)
        if (process->ns[i])
            get_ipc_info(process->ns[i]);

    memcpy(&cur_process, process, sizeof(struct shim_process));
    // this lock will be created in init_ipc
    clear_lock(&cur_process.lock);

    DEBUG_RS("vmid=%u,uri=%s,parent=%u(%s)", process->vmid,
             process->self ? qstrgetstr(&process->self->uri) : "",
             process->parent ? process->parent->vmid : 0,
             process->parent ? qstrgetstr(&process->parent->uri) : "");
}
END_RS_FUNC(process)
