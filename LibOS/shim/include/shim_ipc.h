/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef SHIM_IPC_H_
#define SHIM_IPC_H_

#include "avl_tree.h"
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

#define IPC_SEM_NOTIMEOUT    ((unsigned long)-1)

enum {
    IPC_MSG_RESP = 0,
    IPC_MSG_CONNBACK,      /*!< Request for establishing a connection to the sender. */
    IPC_MSG_DUMMY,         /*!< Dummy callback, wakes up the thread waiting for this response. */
    IPC_MSG_CHILDEXIT,
    IPC_MSG_LEASE,
    IPC_MSG_OFFER,
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

struct shim_ipc_ids {
    IDTYPE parent_vmid;
    IDTYPE leader_vmid;
};

extern IDTYPE g_self_vmid;
extern struct shim_ipc_ids g_process_ipc_ids;

int init_ipc(void);
int init_ns_ranges(void);
int init_ns_pid(void);
int init_ns_sysv(void);

/*!
 * \brief Initialize the IPC worker thread
 */
int init_ipc_worker(void);
/*!
 * \brief Terminate the IPC worker thread
 */
void terminate_ipc_worker(void);

/*!
 * \brief Establish a one-way IPC connection to another process
 *
 * \param dest vmid of the destination process to connect to
 */
int connect_to_process(IDTYPE dest);
/*!
 * \brief Remove an outgoing IPC connection
 *
 * \param dest vmid of the destination process
 *
 * If there is no outgoing connection to \p dest, does nothing.
 */
void remove_outgoing_ipc_connection(IDTYPE dest);
/*!
 * \brief Request the IPC leader to open a one-way connection to this process
 *
 * This makes sure that the IPC leader has an open connection to this process and includes it in all
 * broadcast IPC messages.
 */
int request_leader_connect_back(void);

/* TODO: add `__attribute__((packed))` once `struct shim_ipc_msg` is removed.
 * Currently we might send some padding bytes, but that's not a problem since we only send those
 * between Graphene processes, which are all considered equally trusted. */
struct ipc_msg_header {
    size_t size;
    unsigned long seq;
    unsigned char code;
};

struct shim_ipc_msg {
    struct ipc_msg_header header;
    char data[];
};
/*
 * XXX: Currently required by:
 * - `msg_add_range` in `LibOS/shim/src/ipc/shim_ipc_ranges.c`,
 * - `msgsnd_callback` in `LibOS/shim/src/ipc/shim_ipc_sysv.c`,
 * - `semret_callback` in `LibOS/shim/src/ipc/shim_ipc_sysv.c`.
 */
static_assert(offsetof(struct shim_ipc_msg, data) % 8 == 0, "Currently proper alignment is required");

struct shim_ipc_msg_with_ack {
    struct avl_tree_node node;
    struct shim_thread* thread;
    int retval;
    void* private;
    struct shim_ipc_msg msg;
};

struct shim_ipc_resp {
    int retval;
} __attribute__((packed));

static inline size_t get_ipc_msg_size(size_t payload) {
    return sizeof(struct shim_ipc_msg) + payload;
}
static inline size_t get_ipc_msg_with_ack_size(size_t payload) {
    return sizeof(struct shim_ipc_msg_with_ack) + payload;
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size);
void init_ipc_msg_with_ack(struct shim_ipc_msg_with_ack* msg, int code, size_t size);

/*!
 * \brief Send an IPC message
 *
 * \param msg message to send
 * \param dest vmid of the destination process
 */
int send_ipc_message(struct shim_ipc_msg* msg, IDTYPE dest);
/*!
 * \brief Send an IPC message and wait for response
 *
 * \param msg message to send
 * \param dest vmid of the destination process
 * \param[out] seq upon return contains sequence number of this message
 *
 * Send an IPC message to the \p dest process and wait for a response. An unique number is assigned
 * before sending the message and this thread will wait for a response IPC message, which contains
 * the same sequence number.
 */
int send_ipc_message_with_ack(struct shim_ipc_msg_with_ack* msg, IDTYPE dest, unsigned long* seq);
/*!
 * \brief Broadcast an IPC message
 *
 * \param msg message to send
 * \param exclude_vmid vmid of process to be excluded
 *
 * Send an IPC message \p msg to all known (connected) processes except for \p exclude_vmid.
 */
int broadcast_ipc(struct shim_ipc_msg* msg, IDTYPE exclude_vmid);
/*!
 * \brief Callback for a dummy message, just wakes the waiting thread
 *
 * \param src unused (just for interface conformance)
 * \param data unused (just for interface conformance)
 * \param seq sequence number of the message
 */
int ipc_dummy_callback(IDTYPE src, void* data, unsigned long seq);

/*!
 * \brief Handle a response to a previously sent message
 *
 * \param seq sequence number of the original message
 * \param callback callback to be called on the original message
 * \param data passed as the second argument to \p callback
 *
 * Searches for a `shim_ipc_msg_with_ack` sent previously to \p src, which has \p seq sequential
 * number. Then calls \p callback with the found message (or `NULL` if no message was found) as
 * the first argument and \p data as the second.
 */
void ipc_msg_response_handle(unsigned long seq,
                             void (*callback)(struct shim_ipc_msg_with_ack*, void*), void* data);
/*!
 * \brief Wake up the thread awaiting for a response to \p req_msg
 *
 * \param req_msg original message which got the response
 * \param data unused (just to conform to #ipc_msg_response_handle callbacks interface)
 */
void wake_req_msg_thread(struct shim_ipc_msg_with_ack* req_msg, void* data);

/* common functions for pid & sysv namespaces */
int add_ipc_subrange(IDTYPE idx, IDTYPE owner);
IDTYPE allocate_ipc_id(IDTYPE min, IDTYPE max);
void release_ipc_id(IDTYPE idx);

/*!
 * \brief Find owner of a given id
 *
 * \param idx id to find owner of
 * \parami[out] owner contains vmid of the process owning \p idx.
 */
int find_owner(IDTYPE idx, IDTYPE* owner);

struct ipc_ns_offered {
    IDTYPE base;
    IDTYPE size;
    IDTYPE owner;
} __attribute__((packed));

/* CLD_EXIT: process exit */
struct shim_ipc_cld_exit {
    IDTYPE ppid, pid;
    IDTYPE uid;
    unsigned int exitcode;
    unsigned int term_signal;
} __attribute__((packed));

int ipc_cld_exit_send(unsigned int exitcode, unsigned int term_signal);
int ipc_cld_exit_callback(IDTYPE src, void* data, unsigned long seq);
void ipc_child_disconnect_callback(IDTYPE vmid);

int ipc_lease_send(void);
int ipc_lease_callback(IDTYPE src, void* data, unsigned long seq);

/* OFFER: offer a range of IDs */
struct shim_ipc_offer {
    IDTYPE base;
    IDTYPE size;
} __attribute__((packed));

int ipc_offer_send(IDTYPE dest, IDTYPE base, IDTYPE size, unsigned long seq);
int ipc_offer_callback(IDTYPE src, void* data, unsigned long seq);

/* SUBLEASE: lease a range of IDs */
struct shim_ipc_sublease {
    IDTYPE tenant;
    IDTYPE idx;
} __attribute__((packed));

int ipc_sublease_send(IDTYPE tenant, IDTYPE idx);
int ipc_sublease_callback(IDTYPE src, void* data, unsigned long seq);

/* QUERY: query for a certain ID */
struct shim_ipc_query {
    IDTYPE idx;
} __attribute__((packed));

int ipc_query_send(IDTYPE idx);
int ipc_query_callback(IDTYPE src, void* data, unsigned long seq);

/* QUERYALL: query for all IDs */
int ipc_queryall_send(void);
int ipc_queryall_callback(IDTYPE src, void* data, unsigned long seq);

/* ANSWER: reply to the query with my offered IDs */
struct shim_ipc_answer {
    size_t answers_cnt;
    struct ipc_ns_offered answers[];
} __attribute__((packed));

int ipc_answer_callback(IDTYPE src, void* data, unsigned long seq);

/* PID_KILL: send signal to certain pid */
struct shim_ipc_pid_kill {
    IDTYPE sender;
    enum kill_type type;
    IDTYPE id;
    int signum;
} __attribute__((packed));

int ipc_kill_process(IDTYPE sender, IDTYPE target, int sig);
int ipc_kill_thread(IDTYPE sender, IDTYPE dest_pid, IDTYPE target, int sig);
int ipc_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig);
int ipc_kill_all(IDTYPE sender, int sig);
int ipc_pid_kill_callback(IDTYPE src, void* data, unsigned long seq);

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

int ipc_pid_getstatus_send(IDTYPE dest, int npids, IDTYPE* pids, struct pid_status** status);
int ipc_pid_getstatus_callback(IDTYPE src, void* data, unsigned long seq);

/* PID_RETSTATUS: return status of pid(s) */
struct shim_ipc_pid_retstatus {
    int nstatus;
    struct pid_status status[];
} __attribute__((packed));

int ipc_pid_retstatus_send(IDTYPE dest, int nstatus, struct pid_status* status, unsigned long seq);
int ipc_pid_retstatus_callback(IDTYPE src, void* data, unsigned long seq);

int get_all_pid_status(struct pid_status** status);

/* PID_GETMETA: get metadata of certain pid */
struct shim_ipc_pid_getmeta {
    IDTYPE pid;
    enum pid_meta_code code;
} __attribute__((packed));

int ipc_pid_getmeta_send(IDTYPE pid, enum pid_meta_code code, void** data);
int ipc_pid_getmeta_callback(IDTYPE src, void* data, unsigned long seq);

/* PID_RETMETA: return metadata of certain pid */
struct shim_ipc_pid_retmeta {
    IDTYPE pid;
    enum pid_meta_code code;
    int datasize;
    char data[];
} __attribute__((packed));

int ipc_pid_retmeta_send(IDTYPE dest, IDTYPE pid, enum pid_meta_code code, const void* data,
                         int datasize, unsigned long seq);
int ipc_pid_retmeta_callback(IDTYPE src, void* data, unsigned long seq);

/* sysv namespace */
struct sysv_key {
    unsigned long key;
    enum sysv_type type;
};

int sysv_add_key(struct sysv_key* key, IDTYPE id);
int sysv_get_key(struct sysv_key* key, bool delete);

/* SYSV_FINDKEY */
struct shim_ipc_sysv_findkey {
    struct sysv_key key;
} __attribute__((packed));

int ipc_sysv_findkey_send(struct sysv_key* key);
int ipc_sysv_findkey_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_TELLKEY */
struct shim_ipc_sysv_tellkey {
    struct sysv_key key;
    IDTYPE id;
} __attribute__((packed));

int ipc_sysv_tellkey_send(IDTYPE dest, struct sysv_key* key, IDTYPE id, unsigned long seq);
int ipc_sysv_tellkey_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_DELRES */
struct shim_ipc_sysv_delres {
    IDTYPE resid;
    enum sysv_type type;
} __attribute__((packed));

int ipc_sysv_delres_send(IDTYPE dest, IDTYPE resid, enum sysv_type type);
int ipc_sysv_delres_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_MSGSND */
struct shim_ipc_sysv_msgsnd {
    IDTYPE msgid;
    long msgtype;
    size_t size;
    char msg[];
} __attribute__((packed));

int ipc_sysv_msgsnd_send(IDTYPE dest, IDTYPE msgid, long msgtype, const void* buf, size_t size,
                         unsigned long seq);
int ipc_sysv_msgsnd_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_MSGRCV */
struct shim_ipc_sysv_msgrcv {
    IDTYPE msgid;
    long msgtype;
    size_t size;
    int flags;
} __attribute__((packed));

int ipc_sysv_msgrcv_send(IDTYPE msgid, long msgtype, int flags, void* buf, size_t size);
int ipc_sysv_msgrcv_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_SEMOP */
struct shim_ipc_sysv_semop {
    IDTYPE semid;
    unsigned long timeout;
    int nsops;
    struct sembuf sops[];
};

int ipc_sysv_semop_send(IDTYPE semid, struct sembuf* sops, int nsops, unsigned long timeout,
                        unsigned long* seq);
int ipc_sysv_semop_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_SEMCTL */
struct shim_ipc_sysv_semctl {
    IDTYPE semid;
    int semnum;
    int cmd;
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semctl_send(IDTYPE semid, int semnum, int cmd, void* vals, size_t valsize);
int ipc_sysv_semctl_callback(IDTYPE src, void* data, unsigned long seq);

/* SYSV_SEMRET */
struct shim_ipc_sysv_semret {
    size_t valsize;
    unsigned char vals[];
} __attribute__((packed));

int ipc_sysv_semret_send(IDTYPE dest, void* vals, size_t valsize, unsigned long seq);
int ipc_sysv_semret_callback(IDTYPE src, void* data, unsigned long seq);

#endif /* SHIM_IPC_H_ */
