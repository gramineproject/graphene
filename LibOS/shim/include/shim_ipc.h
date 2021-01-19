/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Definitions of types and functions for IPC bookkeeping.
 */

#ifndef _SHIM_IPC_H_
#define _SHIM_IPC_H_

#include "list.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_sysv.h"
#include "shim_thread.h"
#include "shim_types.h"

/* if callback func returns RESPONSE_CALLBACK, send response msg even if callback succeeded */
#define RESPONSE_CALLBACK 1

#define RANGE_SIZE 32
#define LEASE_TIME 1000

#define IPC_MSG_MINIMAL_SIZE 48
#define IPC_SEM_NOTIMEOUT    ((unsigned long)-1)
#define MAX_IPC_PORT_FINI_CB 3

enum {
    IPC_LISTENING,    /* listening port; processes connect to it to create connection ports */
    IPC_CONNECTION,   /* processes communicate on ports of this type */
    IPC_DIRECTCHILD,  /* direct child: used to broadcast messages to children processes */
    IPC_DIRECTPARENT, /* direct parent: used to broadcast messages to parent process */
};

enum {
    IPC_PORT_LISTENING    = 1 << IPC_LISTENING,
    IPC_PORT_CONNECTION   = 1 << IPC_CONNECTION,
    IPC_PORT_DIRECTCHILD  = 1 << IPC_DIRECTCHILD,
    IPC_PORT_DIRECTPARENT = 1 << IPC_DIRECTPARENT,
};

enum {
    IPC_MSG_RESP = 0,
    IPC_MSG_CHILDEXIT,
    IPC_MSG_FINDNS,
    IPC_MSG_TELLNS,
    IPC_MSG_LEASE,
    IPC_MSG_OFFER,
    IPC_MSG_RENEW,
    IPC_MSG_SUBLEASE,
    IPC_MSG_QUERY,
    IPC_MSG_QUERYALL,
    IPC_MSG_ANSWER,
    IPC_MSG_PID_KILL,
    IPC_MSG_PID_GETSTATUS,
    IPC_MSG_PID_RETSTATUS,
    IPC_MSG_PID_GETMETA,
    IPC_MSG_PID_RETMETA,
    IPC_MSG_SYSV_FINDKEY,
    IPC_MSG_SYSV_TELLKEY,
    IPC_MSG_SYSV_DELRES,
    IPC_MSG_SYSV_MOVRES,
    IPC_MSG_SYSV_MSGSND,
    IPC_MSG_SYSV_MSGRCV,
    IPC_MSG_SYSV_SEMOP,
    IPC_MSG_SYSV_SEMCTL,
    IPC_MSG_SYSV_SEMRET,
    IPC_MSG_CODE_BOUND,
};

enum kill_type { KILL_THREAD, KILL_PROCESS, KILL_PGROUP, KILL_ALL };

enum pid_meta_code { PID_META_CRED, PID_META_EXEC, PID_META_CWD, PID_META_ROOT };

enum sysv_type { SYSV_NONE, SYSV_MSGQ, SYSV_SEM, SYSV_SHM };

DEFINE_LIST(shim_ipc_info);
struct shim_ipc_info {
    IDTYPE vmid;
    struct shim_ipc_port* port;
    PAL_HANDLE pal_handle;
    struct shim_qstr uri;
    LIST_TYPE(shim_ipc_info) hlist;
    REFTYPE ref_count;
};

struct shim_process_ipc_info {
    IDTYPE vmid;
    struct shim_lock lock;
    struct shim_ipc_info* self;
    struct shim_ipc_info* parent;
    struct shim_ipc_info* ns;
};

extern struct shim_process_ipc_info g_process_ipc_info;

struct shim_ipc_msg {
    unsigned char code;
    size_t size;
    IDTYPE src, dst;
    unsigned long seq;
    /* msg is used to store and read various structures, we need to ensure its proper alignment */
    // TODO: this is only a temporary workaround until we rewrite the IPC subsystem.
    char msg[] __attribute__((aligned(16)));
} __attribute__((packed));

struct shim_ipc_port;
struct shim_thread;

DEFINE_LIST(shim_ipc_msg_with_ack);
struct shim_ipc_msg_with_ack {
    struct shim_thread* thread;
    LIST_TYPE(shim_ipc_msg_with_ack) list;
    int retval;
    void* private;
    struct shim_ipc_msg msg;
};

typedef void (*port_fini)(struct shim_ipc_port*, IDTYPE vmid);

DEFINE_LIST(shim_ipc_port);
DEFINE_LISTP(shim_ipc_msg_with_ack);
struct shim_ipc_port {
    PAL_HANDLE pal_handle;

    REFTYPE ref_count;
    LIST_TYPE(shim_ipc_port) list;
    LISTP_TYPE(shim_ipc_msg_with_ack) msgs;
    struct shim_lock msgs_lock;

    port_fini fini[MAX_IPC_PORT_FINI_CB];

    IDTYPE type;
    IDTYPE vmid;
};

/* common functions for pid & sysv namespaces */
int add_ipc_subrange(IDTYPE idx, IDTYPE owner, const char* uri);
IDTYPE allocate_ipc_id(IDTYPE min, IDTYPE max);
void release_ipc_id(IDTYPE idx);

int connect_ns(IDTYPE* vmid, struct shim_ipc_port** portptr);
int connect_owner(IDTYPE idx, struct shim_ipc_port** portptr, IDTYPE* owner);

/* sysv namespace */
struct sysv_key {
    unsigned long key;
    enum sysv_type type;
};

int sysv_add_key(struct sysv_key* key, IDTYPE id);
int sysv_get_key(struct sysv_key* key, bool delete);

/* common message structs */
struct shim_ipc_resp {
    int retval;
} __attribute__((packed));

struct ipc_ns_offered {
    IDTYPE base;
    IDTYPE size;
    size_t owner_offset;
} __attribute__((packed));

struct ipc_ns_client {
    IDTYPE vmid;
    char uri[1];
} __attribute__((packed));

/* CLD_EXIT: process exit */
struct shim_ipc_cld_exit {
    IDTYPE ppid, pid;
    IDTYPE uid;
    unsigned int exitcode;
    unsigned int term_signal;
} __attribute__((packed));

int ipc_cld_exit_send(unsigned int exitcode, unsigned int term_signal);
int ipc_cld_exit_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* FINDNS: find namespace leader (its IPC port) */
int ipc_findns_send(bool block);
int ipc_findns_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* TELLNS: tell namespace leader (its IPC port) */
struct shim_ipc_tellns {
    IDTYPE vmid;
    char uri[1];
} __attribute__((packed));

int ipc_tellns_send(struct shim_ipc_port* port, IDTYPE dest, struct shim_ipc_info* leader,
                    unsigned long seq);
int ipc_tellns_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* LEASE: lease a range of IDs */
struct shim_ipc_lease {
    char uri[1];
} __attribute__((packed));

int ipc_lease_send(void);
int ipc_lease_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* OFFER: offer a range of IDs */
struct shim_ipc_offer {
    IDTYPE base;
    IDTYPE size;
} __attribute__((packed));

int ipc_offer_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE base, IDTYPE size,
                   unsigned long seq);
int ipc_offer_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* RENEW: renew lease of a range of IDs */
struct shim_ipc_renew {
    IDTYPE base;
    IDTYPE size;
} __attribute__((packed));

int ipc_renew_send(IDTYPE base, IDTYPE size);
int ipc_renew_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SUBLEASE: lease a range of IDs */
struct shim_ipc_sublease {
    IDTYPE tenant;
    IDTYPE idx;
    char uri[1];
} __attribute__((packed));

int ipc_sublease_send(IDTYPE tenant, IDTYPE idx, const char* uri);
int ipc_sublease_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* QUERY: query the IPC port for a certain ID */
struct shim_ipc_query {
    IDTYPE idx;
} __attribute__((packed));

int ipc_query_send(IDTYPE idx);
int ipc_query_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* QUERYALL: query the IPC port for all IDs */
int ipc_queryall_send(void);
int ipc_queryall_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* ANSWER: reply to the query with my offered IDs */
struct shim_ipc_answer {
    size_t answers_cnt;
    struct ipc_ns_offered answers[];
} __attribute__((packed));

int ipc_answer_send(struct shim_ipc_port* port, IDTYPE dest, size_t answers_cnt,
                    struct ipc_ns_offered* answers, size_t owners_cnt,
                    struct ipc_ns_client** ownerdata, size_t* ownerdatasz, unsigned long seq);
int ipc_answer_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* PID_KILL: send signal to certain pid */
struct shim_ipc_pid_kill {
    IDTYPE sender;
    enum kill_type type;
    IDTYPE id;
    int signum;
} __attribute__((packed));

int ipc_pid_kill_send(IDTYPE sender, IDTYPE target, enum kill_type type, int signum);
int ipc_pid_kill_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* PID_GETSTATUS: check if certain pid(s) exists */
struct shim_ipc_pid_getstatus {
    int npids;
    IDTYPE pids[];
};

struct pid_status {
    IDTYPE pid;
    IDTYPE tgid;
    IDTYPE pgid;
} __attribute__((packed));

int ipc_pid_getstatus_send(struct shim_ipc_port* port, IDTYPE dest, int npids, IDTYPE* pids,
                           struct pid_status** status);
int ipc_pid_getstatus_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* PID_RETSTATUS: return status of pid(s) */
struct shim_ipc_pid_retstatus {
    int nstatus;
    struct pid_status status[];
} __attribute__((packed));

int ipc_pid_retstatus_send(struct shim_ipc_port* port, IDTYPE dest, int nstatus,
                           struct pid_status* status, unsigned long seq);
int ipc_pid_retstatus_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* PID_GETMETA: get metadata of certain pid */
struct shim_ipc_pid_getmeta {
    IDTYPE pid;
    enum pid_meta_code code;
} __attribute__((packed));

int ipc_pid_getmeta_send(IDTYPE pid, enum pid_meta_code code, void** data);
int ipc_pid_getmeta_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

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
int ipc_pid_retmeta_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_FINDKEY */
struct shim_ipc_sysv_findkey {
    struct sysv_key key;
} __attribute__((packed));

int ipc_sysv_findkey_send(struct sysv_key* key);
int ipc_sysv_findkey_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_TELLKEY */
struct shim_ipc_sysv_tellkey {
    struct sysv_key key;
    IDTYPE id;
} __attribute__((packed));

int ipc_sysv_tellkey_send(struct shim_ipc_port* port, IDTYPE dest, struct sysv_key* key, IDTYPE id,
                          unsigned long seq);
int ipc_sysv_tellkey_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_DELRES */
struct shim_ipc_sysv_delres {
    IDTYPE resid;
    enum sysv_type type;
} __attribute__((packed));

int ipc_sysv_delres_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE resid,
                         enum sysv_type type);
int ipc_sysv_delres_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_MOVRES */
struct shim_ipc_sysv_movres {
    IDTYPE resid;
    enum sysv_type type;
    IDTYPE owner;
    char uri[1];
};

int ipc_sysv_movres_send(struct sysv_client* client, IDTYPE owner, const char* uri, IDTYPE resid,
                         enum sysv_type type);
int ipc_sysv_movres_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_MSGSND */
struct shim_ipc_sysv_msgsnd {
    IDTYPE msgid;
    long msgtype;
    char msg[];
} __attribute__((packed));

int ipc_sysv_msgsnd_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, long msgtype,
                         const void* buf, size_t size, unsigned long seq);
int ipc_sysv_msgsnd_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_MSGRCV */
struct shim_ipc_sysv_msgrcv {
    IDTYPE msgid;
    long msgtype;
    size_t size;
    int flags;
} __attribute__((packed));

int ipc_sysv_msgrcv_send(IDTYPE msgid, long msgtype, int flags, void* buf, size_t size);
int ipc_sysv_msgrcv_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_SEMOP */
struct shim_ipc_sysv_semop {
    IDTYPE semid;
    unsigned long timeout;
    int nsops;
    struct sembuf sops[];
};

int ipc_sysv_semop_send(IDTYPE semid, struct sembuf* sops, int nsops, unsigned long timeout,
                        unsigned long* seq);
int ipc_sysv_semop_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_SEMCTL */
struct shim_ipc_sysv_semctl {
    IDTYPE semid;
    int semnum;
    int cmd;
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semctl_send(IDTYPE semid, int semnum, int cmd, void* vals, size_t valsize);
int ipc_sysv_semctl_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* SYSV_SEMRET */
struct shim_ipc_sysv_semret {
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semret_send(struct shim_ipc_port* port, IDTYPE dest, void* vals, size_t valsize,
                         unsigned long seq);
int ipc_sysv_semret_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

/* general-purpose routines */
int init_ipc(void);
int init_ipc_helper(void);

struct shim_process_ipc_info* create_process_ipc_info(void);
void free_process_ipc_info(struct shim_process_ipc_info* process);

struct shim_ipc_info* create_ipc_info_and_port(bool use_vmid_as_port_name);
int get_ipc_info_cur_process(struct shim_ipc_info** pinfo);

void add_ipc_port_by_id(IDTYPE vmid, PAL_HANDLE hdl, IDTYPE type, port_fini fini,
                        struct shim_ipc_port** portptr);
void add_ipc_port(struct shim_ipc_port* port, IDTYPE vmid, IDTYPE type, port_fini fini);
void del_ipc_port_fini(struct shim_ipc_port* port);
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

static inline size_t get_ipc_msg_size(size_t payload) {
    size_t size = sizeof(struct shim_ipc_msg) + payload;
    return (size > IPC_MSG_MINIMAL_SIZE) ? size : IPC_MSG_MINIMAL_SIZE;
}

static inline size_t get_ipc_msg_with_ack_size(size_t payload) {
    static_assert(sizeof(struct shim_ipc_msg_with_ack) >= sizeof(struct shim_ipc_msg),
                  "Incorrect shim_ipc_msg_with_ack size");
    return get_ipc_msg_size(payload) +
           (sizeof(struct shim_ipc_msg_with_ack) - sizeof(struct shim_ipc_msg));
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size, IDTYPE dest);
void init_ipc_msg_with_ack(struct shim_ipc_msg_with_ack* msg, int code, size_t size, IDTYPE dest);

struct shim_ipc_msg_with_ack* pop_ipc_msg_with_ack(struct shim_ipc_port* port, unsigned long seq);

int broadcast_ipc(struct shim_ipc_msg* msg, int target_type, struct shim_ipc_port* exclude_port);
int send_ipc_message(struct shim_ipc_msg* msg, struct shim_ipc_port* port);
int send_ipc_message_with_ack(struct shim_ipc_msg_with_ack* msg, struct shim_ipc_port* port,
                              unsigned long* seq, void* private_data);
int send_response_ipc_message(struct shim_ipc_port* port, IDTYPE dest, int ret, unsigned long seq);

void ipc_port_with_child_fini(struct shim_ipc_port* port, IDTYPE vmid);

struct shim_thread* terminate_ipc_helper(void);

int prepare_ipc_leader(void);

int init_ipc_ports(void);
int init_ns_ranges(void);
int init_ns_pid(void);
int init_ns_sysv(void);

int get_all_pid_status(struct pid_status** status);

#endif /* _SHIM_IPC_H_ */
