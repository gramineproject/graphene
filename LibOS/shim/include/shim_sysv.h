/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file includes functions and types for implementing System V IPC functionality.
 */

#ifndef __SHIM_SYSV_H__
#define __SHIM_SYSV_H__

#include "list.h"
#include "shim_handle.h"
#include "shim_types.h"

#define SYSV_TYPE_STR(type)       \
    ((type) == SYSV_MSGQ ? "MSGQ" \
                         : ((type) == SYSV_SEM ? "SEM" : ((type) == SYSV_SHM ? "SHM" : "")))

struct sysv_client {
    struct shim_ipc_port* port;
    IDTYPE vmid;
    unsigned seq;
};

struct shim_handle;

#define MSG_NOERROR 010000

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

int add_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, const void* data,
                 struct sysv_client* src);
int get_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, void* data, int flags,
                 struct sysv_client* src);

int store_all_msg_persist(void);

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

int add_sem_handle(unsigned long key, IDTYPE id, int nsems, bool owned);
struct shim_sem_handle* get_sem_handle_by_key(unsigned long key);
struct shim_sem_handle* get_sem_handle_by_id(IDTYPE semid);
void put_sem_handle(struct shim_sem_handle* sem);
int del_sem_handle(struct shim_sem_handle* sem);

int submit_sysv_sem(struct shim_sem_handle* sem, struct sembuf* sops, int nsops,
                    unsigned long timeout, struct sysv_client* client);

#endif /* __SHIM_SYSV_H__ */
