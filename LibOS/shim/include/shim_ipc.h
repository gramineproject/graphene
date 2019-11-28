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
 * shim_ipc.h
 *
 * Definitions of types and functions for IPC bookkeeping.
 */

#ifndef _SHIM_IPC_H_
#define _SHIM_IPC_H_

#include <list.h>
#include <pal.h>
#include <shim_defs.h>
#include <shim_handle.h>
#include <shim_sysv.h>
#include <shim_thread.h>
#include <shim_types.h>

DEFINE_LIST(shim_ipc_info);
struct shim_ipc_info {
    IDTYPE vmid;
    struct shim_ipc_port* port;
    PAL_HANDLE pal_handle;
    struct shim_qstr uri;
    LIST_TYPE(shim_ipc_info) hlist;
    REFTYPE ref_count;
};

enum { PID_NS, SYSV_NS, TOTAL_NS };

struct shim_process {
    IDTYPE vmid;
    struct shim_lock lock;
    int exit_code;
    struct shim_ipc_info* self;
    struct shim_ipc_info* parent;
    struct shim_ipc_info* ns[TOTAL_NS];
};

extern struct shim_process cur_process;

#define IPC_MSG_MINIMAL_SIZE 48

struct shim_ipc_msg {
    unsigned char code;
    size_t size;
    IDTYPE src, dst;
    unsigned long seq;
#ifdef PROFILE
    unsigned long time;
#endif
    char msg[];
} __attribute__((packed));

struct shim_ipc_port;
struct shim_thread;

DEFINE_LIST(shim_ipc_msg_duplex);
struct shim_ipc_msg_duplex {
    struct shim_thread* thread;
    LIST_TYPE(shim_ipc_msg_duplex) list;
    int retval;
    void* private;
    struct shim_ipc_msg msg;
};

typedef void (*port_fini)(struct shim_ipc_port*, IDTYPE vmid, unsigned int exitcode);

#define MAX_IPC_PORT_FINI_CB 3

DEFINE_LIST(shim_ipc_port);
DEFINE_LISTP(shim_ipc_msg_duplex);
struct shim_ipc_port {
    PAL_HANDLE pal_handle;

    REFTYPE ref_count;
    LIST_TYPE(shim_ipc_port) list;
    LISTP_TYPE(shim_ipc_msg_duplex) msgs;
    struct shim_lock msgs_lock;

    port_fini fini[MAX_IPC_PORT_FINI_CB];

    IDTYPE type;
    IDTYPE vmid;
};

#define IPC_CALLBACK_ARGS struct shim_ipc_msg* msg, struct shim_ipc_port* port

/* if callback return RESPONSE_CALLBACK, send a response even if the callback
   succeed. */
#define RESPONSE_CALLBACK 1

typedef int (*ipc_callback)(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* Basic message codes */
enum {
    IPC_RESP = 0,
    IPC_CHECKPOINT,
    IPC_BASE_BOUND,
};

/* IPC_RESP: response for incoming messages */
struct shim_ipc_resp {
    int retval;
} __attribute__((packed));

/* PID_CHECKPOINT: broadcast checkpointing */
struct shim_ipc_checkpoint {
    IDTYPE cpsession;
    char cpdir[];
};

int ipc_checkpoint_send(const char* cpdir, IDTYPE cpsession);
int ipc_checkpoint_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* Message code from child to parent */
#define IPC_CLD_BASE IPC_BASE_BOUND
enum {
    IPC_CLD_EXIT = IPC_CLD_BASE,
#ifdef PROFILE
    IPC_CLD_PROFILE,
#endif
    IPC_CLD_BOUND,
};

/* CLD_EXIT: thread exit */
struct shim_ipc_cld_exit {
    IDTYPE ppid, tid;
    unsigned int exitcode;
    unsigned int term_signal;
#ifdef PROFILE
    unsigned long time;
#endif
} __attribute__((packed));

int ipc_cld_exit_send(IDTYPE ppid, IDTYPE tid, unsigned int exitcode, unsigned int term_signal);
int ipc_cld_exit_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

#ifdef PROFILE
#include <shim_profile.h>

struct shim_ipc_cld_profile {
    unsigned long time;
    int nprofile;
    struct profile_val profile[];
} __attribute__((packed));

int ipc_cld_profile_send(void);
int ipc_cld_profile_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);
#endif

/* Message code to namespace manager */
#define IPC_PID_BASE IPC_CLD_BOUND

#define NS     pid
#define NS_CAP PID

#include "shim_ipc_ns.h"

enum {
    IPC_PID_KILL = IPC_PID_TEMPLATE_BOUND,
    IPC_PID_GETSTATUS,
    IPC_PID_RETSTATUS,
    IPC_PID_GETMETA,
    IPC_PID_RETMETA,
    IPC_PID_NOP,
    IPC_PID_SENDRPC,
    IPC_PID_BOUND,
};

enum kill_type { KILL_THREAD, KILL_PROCESS, KILL_PGROUP, KILL_ALL };

/* PID_KILL: send signal to certain pid */
struct shim_ipc_pid_kill {
    IDTYPE sender;
    enum kill_type type;
    IDTYPE id;
    int signum;
} __attribute__((packed));

int ipc_pid_kill_send(IDTYPE sender, IDTYPE target, enum kill_type type, int signum);
int ipc_pid_kill_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

struct pid_status {
    IDTYPE pid, tgid, pgid;
} __attribute__((packed));

/* PID_GETSTATUS: check if certain pid(s) exists */
struct shim_ipc_pid_getstatus {
    int npids;
    IDTYPE pids[];
};

int ipc_pid_getstatus_send(struct shim_ipc_port* port, IDTYPE dest, int npids, IDTYPE* pids,
                           struct pid_status** status);
int ipc_pid_getstatus_callback(IPC_CALLBACK_ARGS);

/* PID_RETSTATUS: return status of pid(s) */
struct shim_ipc_pid_retstatus {
    int nstatus;
    struct pid_status status[];
} __attribute__((packed));

int ipc_pid_retstatus_send(struct shim_ipc_port* port, IDTYPE dest, int nstatus,
                           struct pid_status* status, unsigned long seq);
int ipc_pid_retstatus_callback(IPC_CALLBACK_ARGS);

/* PID_GETMETA: get metadata of certain pid */
enum pid_meta_code {
    PID_META_CRED,
    PID_META_EXEC,
    PID_META_CWD,
    PID_META_ROOT,
};

struct shim_ipc_pid_getmeta {
    IDTYPE pid;
    enum pid_meta_code code;
} __attribute__((packed));

int ipc_pid_getmeta_send(IDTYPE pid, enum pid_meta_code code, void** data);
int ipc_pid_getmeta_callback(IPC_CALLBACK_ARGS);

/* PID_RETMETA: return metadata of certain pid */
struct shim_ipc_pid_retmeta {
    IDTYPE pid;
    enum pid_meta_code code;
    int datasize;
    char data[];
} __attribute__((packed));

int ipc_pid_retmeta_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE pid,
                         enum pid_meta_code code, const void* data, int datasize,
                         unsigned long seq);
int ipc_pid_retmeta_callback(IPC_CALLBACK_ARGS);

/* PID_NOP: send junk message (for benchmarking) */
struct shim_ipc_pid_nop {
    int count;
    char payload[];
} __attribute__((packed));

int ipc_pid_nop_send(struct shim_ipc_port* port, IDTYPE dest, int count, const void* buf, int len);
int ipc_pid_nop_callback(IPC_CALLBACK_ARGS);

/* PID_SENDRPC: send arbitary message (for benchmarking) */
struct shim_ipc_pid_sendrpc {
    IDTYPE sender;
    int len;
    char payload[];
} __attribute__((packed));

int ipc_pid_sendrpc_send(IDTYPE pid, IDTYPE sender, const void* buf, int len);
int ipc_pid_sendrpc_callback(IPC_CALLBACK_ARGS);

#define IPC_SYSV_BASE IPC_PID_BOUND

struct sysv_key {
    unsigned long key;
    enum sysv_type type;
};

#define NS     sysv
#define NS_CAP SYSV
#define NS_KEY struct sysv_key

#include "shim_ipc_ns.h"

enum {
    IPC_SYSV_DELRES = IPC_SYSV_TEMPLATE_BOUND,
    IPC_SYSV_MOVRES,
    IPC_SYSV_MSGSND,
    IPC_SYSV_MSGRCV,
    IPC_SYSV_MSGMOV,
    IPC_SYSV_SEMOP,
    IPC_SYSV_SEMCTL,
    IPC_SYSV_SEMRET,
    IPC_SYSV_SEMMOV,
#ifdef USE_SHARED_SEMAPHORE
    IPC_SYSV_SEMQUERY,
    IPC_SYSV_SEMREPLY,
#endif
    IPC_SYSV_BOUND,
};

/* SYSV_DELRES */
struct shim_ipc_sysv_delres {
    IDTYPE resid;
    enum sysv_type type;
} __attribute__((packed));

int ipc_sysv_delres_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE resid,
                         enum sysv_type type);
int ipc_sysv_delres_callback(IPC_CALLBACK_ARGS);

/* SYSV_MOVRES */
struct shim_ipc_sysv_movres {
    IDTYPE resid;
    enum sysv_type type;
    IDTYPE owner;
    LEASETYPE lease;
    char uri[1];
};

int ipc_sysv_movres_send(struct sysv_client* client, IDTYPE owner, const char* uri, LEASETYPE lease,
                         IDTYPE resid, enum sysv_type type);
int ipc_sysv_movres_callback(IPC_CALLBACK_ARGS);

/* SYSV_MSGSND */
struct shim_ipc_sysv_msgsnd {
    IDTYPE msgid;
    long msgtype;
    char msg[];
} __attribute__((packed));

int ipc_sysv_msgsnd_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, long msgtype,
                         const void* buf, size_t size, unsigned long seq);
int ipc_sysv_msgsnd_callback(IPC_CALLBACK_ARGS);

/* SYSV_MSGRCV */
struct shim_ipc_sysv_msgrcv {
    IDTYPE msgid;
    long msgtype;
    size_t size;
    int flags;
} __attribute__((packed));

int ipc_sysv_msgrcv_send(IDTYPE msgid, long msgtype, int flags, void* buf, size_t size);
int ipc_sysv_msgrcv_callback(IPC_CALLBACK_ARGS);

/* SYSV_MSGMOV */
struct shim_ipc_sysv_msgmov {
    IDTYPE msgid;
    LEASETYPE lease;
    unsigned short nscores;
    struct sysv_score scores[];
};

int ipc_sysv_msgmov_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, LEASETYPE lease,
                         struct sysv_score* scores, int nscores);
int ipc_sysv_msgmov_callback(IPC_CALLBACK_ARGS);

/* SYSV_SEMOP */
struct shim_ipc_sysv_semop {
    IDTYPE semid;
    unsigned long timeout;
    int nsops;
    struct sembuf sops[];
};

#define IPC_SEM_NOTIMEOUT ((unsigned long)-1)

int ipc_sysv_semop_send(IDTYPE semid, struct sembuf* sops, int nsops, unsigned long timeout,
                        unsigned long* seq);
int ipc_sysv_semop_callback(IPC_CALLBACK_ARGS);

/* SYSV_SEMCTL */
struct shim_ipc_sysv_semctl {
    IDTYPE semid;
    int semnum;
    int cmd;
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semctl_send(IDTYPE semid, int semnum, int cmd, void* vals, size_t valsize);
int ipc_sysv_semctl_callback(IPC_CALLBACK_ARGS);

/* SYSV_SEMRET */
struct shim_ipc_sysv_semret {
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semret_send(struct shim_ipc_port* port, IDTYPE dest, void* vals, size_t valsize,
                         unsigned long seq);
int ipc_sysv_semret_callback(IPC_CALLBACK_ARGS);

/* SYSV_SEMMOV */
struct shim_ipc_sysv_semmov {
    IDTYPE semid;
    LEASETYPE lease;
    unsigned short nsems, nsrcs, nscores;
    struct sem_backup sems[];
};

int ipc_sysv_semmov_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE semid, LEASETYPE lease,
                         struct sem_backup* sems, int nsems, struct sem_client_backup* srcs,
                         int nsrcs, struct sysv_score* scores, int nscores);
int ipc_sysv_semmov_callback(IPC_CALLBACK_ARGS);

#ifdef USE_SHARED_SEMAPHORE
/* SYSV_SEMQUERY */
struct shim_ipc_sysv_semquery {
    IDTYPE semid;
} __attribute__((packed));

int ipc_sysv_semquery_send(IDTYPE semid, int* nsems, PAL_NUM** host_sem_ids);
int ipc_sysv_semquery_callback(IPC_CALLBACK_ARGS);

/* SYSV_SEMREPLY */
struct shim_ipc_sysv_semreply {
    IDTYPE semid;
    int nsems;
    PAL_NUM host_sem_ids[];
} __attribute__((packed));

int ipc_sysv_semreply_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE semid, int nsems,
                           PAL_NUM* host_sem_ids, unsigned long seq);
int ipc_sysv_semreply_callback(IPC_CALLBACK_ARGS);
#endif

#define IPC_CODE_NUM IPC_SYSV_BOUND

/* functions and routines */
int init_ipc(void);
int init_ipc_helper(void);

struct shim_process* create_process(bool dup_cur_process);
void free_process(struct shim_process* process);

struct shim_ipc_info* create_ipc_info_cur_process(bool is_self_ipc_info);
int get_ipc_info_cur_process(struct shim_ipc_info** pinfo);

enum {
    LISTEN,    /* listening */
    SERVER,    /* connect as a server */
    KEEPALIVE, /* keep the connetion alive */
    DIRCLD,    /* direct child */
    DIRPRT,    /* direct parent */
    NS_PORT_CONSTS(PID) NS_PORT_CONSTS(SYSV)
};

enum {
    IPC_PORT_LISTEN    = 1 << LISTEN,
    IPC_PORT_SERVER    = 1 << SERVER,
    IPC_PORT_KEEPALIVE = 1 << KEEPALIVE,
    IPC_PORT_DIRCLD    = 1 << DIRCLD,
    IPC_PORT_DIRPRT    = 1 << DIRPRT,
    NS_PORT_TYPES(PID) NS_PORT_TYPES(SYSV)
};

/* general-purpose routines */
void add_ipc_port_by_id(IDTYPE vmid, PAL_HANDLE hdl, IDTYPE type, port_fini fini,
                        struct shim_ipc_port** portptr);
void add_ipc_port(struct shim_ipc_port* port, IDTYPE vmid, IDTYPE type, port_fini fini);
void del_ipc_port_fini(struct shim_ipc_port* port, unsigned int exitcode);
struct shim_ipc_port* lookup_ipc_port(IDTYPE vmid, IDTYPE type);
void get_ipc_port(struct shim_ipc_port* port);
void put_ipc_port(struct shim_ipc_port* port);
void del_all_ipc_ports(void);

struct shim_ipc_info* create_ipc_info(IDTYPE vmid, const char* uri, size_t len);
void get_ipc_info(struct shim_ipc_info* port);
void put_ipc_info(struct shim_ipc_info* port);

struct shim_ipc_info* create_ipc_info_in_list(IDTYPE vmid, const char* uri, size_t len);
void put_ipc_info_in_list(struct shim_ipc_info* info);
struct shim_ipc_info* lookup_ipc_info(IDTYPE vmid);

static_always_inline size_t get_ipc_msg_size(size_t payload) {
    size_t size = sizeof(struct shim_ipc_msg) + payload;
    return (size > IPC_MSG_MINIMAL_SIZE) ? size : IPC_MSG_MINIMAL_SIZE;
}

static_always_inline size_t get_ipc_msg_duplex_size(size_t payload) {
    static_assert(sizeof(struct shim_ipc_msg_duplex) >= sizeof(struct shim_ipc_msg),
                  "Incorrect shim_ipc_msg_duplex size");
    return get_ipc_msg_size(payload) +
           (sizeof(struct shim_ipc_msg_duplex) - sizeof(struct shim_ipc_msg));
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size, IDTYPE dest);
void init_ipc_msg_duplex(struct shim_ipc_msg_duplex* msg, int code, size_t size, IDTYPE dest);

struct shim_ipc_msg_duplex* pop_ipc_msg_duplex(struct shim_ipc_port* port, unsigned long seq);

int broadcast_ipc(struct shim_ipc_msg* msg, int target_type, struct shim_ipc_port* exclude_port);
int send_ipc_message(struct shim_ipc_msg* msg, struct shim_ipc_port* port);
int send_ipc_message_duplex(struct shim_ipc_msg_duplex* msg, struct shim_ipc_port* port,
                            unsigned long* seq, void* private_data);
int send_response_ipc_message(struct shim_ipc_port* port, IDTYPE dest, int ret, unsigned long seq);

void ipc_port_with_child_fini(struct shim_ipc_port* port, IDTYPE vmid, unsigned int exitcode);

struct shim_thread* terminate_ipc_helper(void);

int prepare_ns_leaders(void);

#endif /* _SHIM_IPC_H_ */
