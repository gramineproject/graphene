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
 * shim_sysv.h
 *
 * This file includes functions and types for implementing System V IPC
 * functionality.
 */

#ifndef __SHIM_SYSV_H__
#define __SHIM_SYSV_H__

#include <shim_handle.h>
#include <shim_types.h>

enum sysv_type { SYSV_NONE, SYSV_MSGQ, SYSV_SEM, SYSV_SHM };

#define SYSV_TYPE_STR(type)       \
    ((type) == SYSV_MSGQ ? "MSGQ" \
                         : ((type) == SYSV_SEM ? "SEM" : ((type) == SYSV_SHM ? "SHM" : "")))

#define VALID_SYSV_TYPE(type) ((type) == SYSV_MSGQ || (type) == SYSV_SEM || (type) == SYSV_SHM)

struct sysv_score {
    IDTYPE vmid;
    unsigned long score;
};

struct sysv_client {
    struct shim_ipc_port* port;
    IDTYPE vmid;
    unsigned seq;
};

struct shim_handle;

struct sysv_balance_policy {
    unsigned int score_decay;
    unsigned int score_max;
    unsigned int balance_threshold;
    int (*migrate)(struct shim_handle* hdl, struct sysv_client* client);
};

int __balance_sysv_score(struct sysv_balance_policy* policy, struct shim_handle* hdl,
                         struct sysv_score* scores, int nscores, struct sysv_client* src,
                         long score);

#define MSG_NOERROR 010000

#include <list.h>

struct __kernel_msgbuf {
    long mtype;   /* type of message */
    char mtext[]; /* message text */
};

#define MSG_QOBJ_SIZE 64

struct msg_qobj {
    void* next;
    char data[MSG_QOBJ_SIZE - sizeof(void*)];
} __attribute__((packed));

struct msg_item {
    void* next;
    unsigned short size;
    char data[];
} __attribute__((packed));

#define MSG_ITEM_DATA_SIZE(size)                               \
    ((size) < MSG_QOBJ_SIZE - sizeof(struct msg_item) ? (size) \
                                                      : MSG_QOBJ_SIZE - sizeof(struct msg_item))

struct msg_ext_item {
    void* next;
    char data[];
} __attribute__((packed));

#define MSG_EXT_ITEM_DATA_SIZE(size)                      \
    ((size) < MSG_QOBJ_SIZE - sizeof(struct msg_ext_item) \
         ? (size)                                         \
         : MSG_QOBJ_SIZE - sizeof(struct msg_ext_item))

struct msg_req {
    struct msg_req* next;
    unsigned short size;
    int flags;
    struct sysv_client dest;
};

#define INIT_MSG_TYPE_SIZE 32

struct msg_type {
    long type; /* type of the messages */
    struct msg_item* msgs;
    struct msg_item* msg_tail;
    struct msg_req* reqs;
    struct msg_req* req_tail;
};

#define DEFAULT_MSG_QUEUE_SIZE 2048

#define MSG_SND_SCORE         1
#define MSG_RCV_SCORE         20
#define MSG_SCORE_DECAY       10
#define MSG_SCORE_MAX         200
#define MSG_BALANCE_THRESHOLD 100

struct msg_handle_backup {
    int perm;        /* access permissions */
    int nmsgs;       /* number of msgs */
    int currentsize; /* current size in bytes */
};

struct msg_backup {
    long type;
    int size;
    char data[];
};

struct shim_msg_handle;

int add_msg_handle(unsigned long key, IDTYPE id, bool owned);
int del_msg_handle(struct shim_msg_handle* msgq);

struct shim_msg_handle* get_msg_handle_by_key(unsigned long key);
struct shim_msg_handle* get_msg_handle_by_id(IDTYPE id);

void put_msg_handle(struct shim_msg_handle* msgq);

int recover_msg_ownership(struct shim_msg_handle* msgq);

int add_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, const void* data,
                 struct sysv_client* src);
int get_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, void* data, int flags,
                 struct sysv_client* src);

int store_all_msg_persist(void);

#define HOST_SEM_NUM 65535

DEFINE_LIST(sem_ops);
struct sem_ops {
    LIST_TYPE(sem_ops) progress;
    struct sem_stat {
        bool completed;
        bool failed;
        int nops;
        int current;
        unsigned long timeout;
    } stat;
    struct sysv_client client;
    struct sembuf ops[];
};

DEFINE_LISTP(sem_ops);
struct sem_obj {
    unsigned short num;
    unsigned short val;
    unsigned short zcnt;
    unsigned short ncnt;
    IDTYPE pid;
    PAL_NUM host_sem_id;
    PAL_HANDLE host_sem;
    LISTP_TYPE(sem_ops) ops;
    LISTP_TYPE(sem_ops) next_ops;
};

#define SEM_POSITIVE_SCORE(num) ((num) < 5 ? 5 - (num) : 1)
#define SEM_ZERO_SCORE          20
#define SEM_NEGATIVE_SCORE(num) (20 * (num))
#define SEM_SCORE_DECAY         10
#define SEM_SCORE_MAX           200
#define SEM_BALANCE_THRESHOLD   100

struct sem_backup {
    unsigned short val;
    unsigned short zcnt;
    unsigned short ncnt;
    IDTYPE pid;
};

struct sem_client_backup {
    IDTYPE vmid;
    unsigned long seq;
    int current;
    int nops;
};

int add_sem_handle(unsigned long key, IDTYPE id, int nsems, bool owned);
struct shim_sem_handle* get_sem_handle_by_key(unsigned long key);
struct shim_sem_handle* get_sem_handle_by_id(IDTYPE semid);
void put_sem_handle(struct shim_sem_handle* sem);
int del_sem_handle(struct shim_sem_handle* sem);

int recover_sem_ownership(struct shim_sem_handle* sem, struct sem_backup* backups, int nbackups,
                          struct sem_client_backup* clients, int nclients);

int submit_sysv_sem(struct shim_sem_handle* sem, struct sembuf* sops, int nsops,
                    unsigned long timeout, struct sysv_client* client);

#ifdef USE_SHARED_SEMAPHORE
int send_sem_host_ids(struct shim_sem_handle* sem, struct shim_ipc_port* port, IDTYPE dest,
                      unsigned long seq);
#endif

#endif /* __SHIM_SYSV_H__ */
