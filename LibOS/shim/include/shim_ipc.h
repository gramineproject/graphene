/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef SHIM_IPC_H_
#define SHIM_IPC_H_

#include <stdint.h>

#include "avl_tree.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_thread.h"
#include "shim_types.h"

#define RANGE_SIZE 32

enum {
    IPC_MSG_RESP = 0,
    IPC_MSG_CONNBACK,      /*!< Request for establishing a connection to the sender. */
    IPC_MSG_CHILDEXIT,
    IPC_MSG_LEASE,
    IPC_MSG_SUBLEASE,
    IPC_MSG_QUERY,
    IPC_MSG_QUERYALL,
    IPC_MSG_PID_KILL,
    IPC_MSG_PID_GETSTATUS,
    IPC_MSG_PID_GETMETA,
    IPC_MSG_SYNC_REQUEST_UPGRADE,
    IPC_MSG_SYNC_REQUEST_DOWNGRADE,
    IPC_MSG_SYNC_REQUEST_CLOSE,
    IPC_MSG_SYNC_CONFIRM_UPGRADE,
    IPC_MSG_SYNC_CONFIRM_DOWNGRADE,
    IPC_MSG_SYNC_CONFIRM_CLOSE,
    IPC_MSG_CODE_BOUND,
};

enum kill_type { KILL_THREAD, KILL_PROCESS, KILL_PGROUP, KILL_ALL };

enum pid_meta_code { PID_META_CRED, PID_META_EXEC, PID_META_CWD, PID_META_ROOT };

struct shim_ipc_ids {
    IDTYPE parent_vmid;
    IDTYPE leader_vmid;
};

extern IDTYPE g_self_vmid;
extern struct shim_ipc_ids g_process_ipc_ids;

int init_ipc(void);
int init_ns_ranges(void);
int init_ns_pid(void);

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
 * If there is no outgoing connection to \p dest, does nothing. If any thread waits for a response
 * to a message sent to \p dest, it is woken up and notified about the disconnect.
 */
void remove_outgoing_ipc_connection(IDTYPE dest);
/*!
 * \brief Request the IPC leader to open a one-way connection to this process
 *
 * This makes sure that the IPC leader has an open connection to this process and includes it in all
 * broadcast IPC messages.
 */
int request_leader_connect_back(void);
/*!
 * \brief Callback for an IPC connection request
 *
 * Parameters as per IPC callback interface.
 * See also: #request_leader_connect_back
 */
int ipc_connect_back_callback(IDTYPE src, void* data, uint64_t seq);

struct ipc_msg_header {
    size_t size;
    uint64_t seq;
    unsigned char code;
} __attribute__((packed));

struct shim_ipc_msg {
    struct ipc_msg_header header;
    char data[];
};

static inline size_t get_ipc_msg_size(size_t payload) {
    return sizeof(struct shim_ipc_msg) + payload;
}

void init_ipc_msg(struct shim_ipc_msg* msg, unsigned char code, size_t size);
void init_ipc_response(struct shim_ipc_msg* msg, uint64_t seq, size_t size);

/*!
 * \brief Send an IPC message
 *
 * \param dest vmid of the destination process
 * \param msg message to send
 */
int ipc_send_message(IDTYPE dest, struct shim_ipc_msg* msg);
/*!
 * \brief Send an IPC message and wait for a response
 *
 * \param dest vmid of the destination process
 * \param msg message to send
 * \param[out] resp upon successful return contains a pointer to the response
 *
 * Send an IPC message to the \p dest process and wait for a response. An unique number is assigned
 * before sending the message and this thread will wait for a response IPC message, which contains
 * the same sequence number. If this function succeeds, \p resp will contain pointer to the response
 * data, which should be freed using `free` function. If \p resp is NULL, the response will be
 * discarded, but still awaited for.
 */
int ipc_send_msg_and_get_response(IDTYPE dest, struct shim_ipc_msg* msg, void** resp);
/*!
 * \brief Broadcast an IPC message
 *
 * \param msg message to send
 * \param exclude_vmid vmid of process to be excluded
 *
 * Send an IPC message \p msg to all known (connected) processes except for \p exclude_vmid.
 */
int ipc_broadcast(struct shim_ipc_msg* msg, IDTYPE exclude_vmid);

/*!
 * \brief Handle a response to a previously sent message
 *
 * \param src ID of sender
 * \param data body of the response
 * \param seq sequence number of the original message
 *
 * Searches for a thread waiting for a response to a message previously sent to \p src with
 * the sequence number \p seq. If such thread is found, it is woken up and \p data is passed to it
 * (returned in `resp` argument of #ipc_send_msg_and_get_response).
 * This function always takes the ownership of \p data, the caller of this function should never
 * free it!
 */
int ipc_response_callback(IDTYPE src, void* data, uint64_t seq);

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
int ipc_cld_exit_callback(IDTYPE src, void* data, uint64_t seq);
void ipc_child_disconnect_callback(IDTYPE vmid);

int ipc_lease_send(void);
int ipc_lease_callback(IDTYPE src, void* data, uint64_t seq);

/* OFFER: offer a range of IDs */
struct shim_ipc_offer {
    IDTYPE base;
    IDTYPE size;
} __attribute__((packed));

/* SUBLEASE: lease a range of IDs */
struct shim_ipc_sublease {
    IDTYPE tenant;
    IDTYPE idx;
} __attribute__((packed));

int ipc_sublease_send(IDTYPE tenant, IDTYPE idx);
int ipc_sublease_callback(IDTYPE src, void* data, uint64_t seq);

/* QUERY: query for a certain ID */
struct shim_ipc_query {
    IDTYPE idx;
} __attribute__((packed));

int ipc_query_send(IDTYPE idx);
int ipc_query_callback(IDTYPE src, void* data, uint64_t seq);

/* QUERYALL: query for all IDs */
int ipc_queryall_send(void);
int ipc_queryall_callback(IDTYPE src, void* data, uint64_t seq);

/* ANSWER: reply to the query with my offered IDs */
struct shim_ipc_answer {
    size_t answers_cnt;
    struct ipc_ns_offered answers[];
} __attribute__((packed));

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
int ipc_pid_kill_callback(IDTYPE src, void* data, uint64_t seq);

/* PID_GETSTATUS: check if certain pid(s) exists */
struct shim_ipc_pid_getstatus {
    size_t npids;
    IDTYPE pids[];
};

struct pid_status {
    IDTYPE pid;
    IDTYPE tgid;
    IDTYPE pgid;
} __attribute__((packed));

/* PID_RETSTATUS: return status of pid(s) */
struct shim_ipc_pid_retstatus {
    size_t count;
    struct pid_status status[];
} __attribute__((packed));

int ipc_pid_getstatus(IDTYPE dest, int npids, IDTYPE* pids, struct shim_ipc_pid_retstatus** status);
int ipc_pid_getstatus_callback(IDTYPE src, void* data, uint64_t seq);

int get_all_pid_status(struct pid_status** status);

/* PID_GETMETA: get metadata of certain pid */
struct shim_ipc_pid_getmeta {
    IDTYPE pid;
    enum pid_meta_code code;
} __attribute__((packed));

/* PID_RETMETA: return metadata of certain pid */
struct shim_ipc_pid_retmeta {
    size_t datasize;
    int ret_val;
    char data[];
} __attribute__((packed));

int ipc_pid_getmeta(IDTYPE pid, enum pid_meta_code code, struct shim_ipc_pid_retmeta** data);
int ipc_pid_getmeta_callback(IDTYPE src, void* data, uint64_t seq);

/* SYNC_REQUEST_*, SYNC_CONFIRM_ */
struct shim_ipc_sync {
    uint64_t id;
    size_t data_size;
    int state;
    unsigned char data[];
};

int ipc_sync_client_send(int code, uint64_t id, int state, size_t data_size, void* data);
int ipc_sync_server_send(IDTYPE dest, int code, uint64_t id, int state, size_t data_size,
                         void* data);
int ipc_sync_request_upgrade_callback(IDTYPE src, void* data, unsigned long seq);
int ipc_sync_request_downgrade_callback(IDTYPE src, void* data, unsigned long seq);
int ipc_sync_request_close_callback(IDTYPE src, void* data, unsigned long seq);
int ipc_sync_confirm_upgrade_callback(IDTYPE src, void* data, unsigned long seq);
int ipc_sync_confirm_downgrade_callback(IDTYPE src, void* data, unsigned long seq);
int ipc_sync_confirm_close_callback(IDTYPE src, void* data, unsigned long seq);

#endif /* SHIM_IPC_H_ */
