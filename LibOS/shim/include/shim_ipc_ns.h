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
 * shim_ipc_ns.h
 *
 * Definitions of types and functions for IPC namespace bookkeeping.
 */

#ifndef __SHIM_IPC_NS_H__
#define __SHIM_IPC_NS_H__

#include <shim_internal.h>
#include <shim_types.h>

#define IPC_NS_CALLBACKS(ns)                                                                \
    /* FINDNS */ &ipc_##ns##_findns_callback, /* TELLNS   */ &ipc_##ns##_tellns_callback,   \
    /* LEASE  */ &ipc_##ns##_lease_callback,  /* OFFER    */ &ipc_##ns##_offer_callback,    \
    /* RENEW  */ &ipc_##ns##_renew_callback,  /* SUBLEASE */ &ipc_##ns##_sublease_callback, \
    /* QUERY  */ &ipc_##ns##_query_callback,  /* QUERYALL */ &ipc_##ns##_queryall_callback, \
    /* ANSWER */ &ipc_##ns##_answer_callback,

#define IPC_NS_KEY_CALLBACKS(ns) \
    /* FINDKEY */ &ipc_##ns##_findkey_callback, /* TELLKEY */ &ipc_##ns##_tellkey_callback,

#define NS_PORT_CONSTS(n) n##CLT, n##LDR, n##CON, n##OWN,

#define NS_PORT_TYPES(n)                                              \
    IPC_PORT_##n##CLT = 1 << n##CLT, IPC_PORT_##n##LDR = 1 << n##LDR, \
    IPC_PORT_##n##CON = 1 << n##CON, IPC_PORT_##n##OWN = 1 << n##OWN,

struct ipc_ns_offered {
    IDTYPE base, size;
    LEASETYPE lease;
    unsigned int owner_offset;
};

struct ipc_ns_client {
    IDTYPE vmid;
    char uri[1];
} __attribute__((packed));

#endif /* __SHIM_IPC_NS_H__ */

#define NS_SEND(t)     CONCAT3(ipc, NS, t##_send)
#define NS_CALLBACK(t) CONCAT3(ipc, NS, t##_callback)
#define NS_CODE(t)     CONCAT3(IPC, NS_CAP, t)
#define NS_MSG_TYPE(t) struct CONCAT3(shim_ipc, NS, t)

int CONCAT3(add, NS, range)(IDTYPE base, IDTYPE owner, const char* uri, LEASETYPE lease);

int CONCAT3(del, NS, range)(IDTYPE idx);

int CONCAT3(add, NS, subrange)(IDTYPE idx, IDTYPE owner, const char* uri, LEASETYPE* lease);

int CONCAT3(del, NS, subrange)(IDTYPE idx);

int CONCAT3(alloc, NS, range)(IDTYPE owner, const char* uri, IDTYPE* base, LEASETYPE* lease);

struct CONCAT2(NS, range) {
    IDTYPE base, size;
    IDTYPE owner;
    struct shim_qstr uri;
    LEASETYPE lease;
    struct shim_ipc_port* port;
};

int CONCAT3(get, NS, range)(IDTYPE idx, struct CONCAT2(NS, range)* range,
                            struct shim_ipc_info** pinfo);
enum {
    NS_CODE(FINDNS) = CONCAT3(IPC, NS_CAP, BASE),
    NS_CODE(TELLNS),
    NS_CODE(LEASE),
    NS_CODE(OFFER),
    NS_CODE(RENEW),
    NS_CODE(SUBLEASE),
    NS_CODE(QUERY),
    NS_CODE(QUERYALL),
    NS_CODE(ANSWER),
#ifdef NS_KEY
    NS_CODE(FINDKEY),
    NS_CODE(TELLKEY),
#endif
    NS_CODE(TEMPLATE_BOUND),
};

/* FINDNS: find the channel of the namespace leader */
int NS_SEND(findns)(bool block);
int NS_CALLBACK(findns)(IPC_CALLBACK_ARGS);

/* TELLNS: tell the channel of namespace leader */
NS_MSG_TYPE(tellns) {
    IDTYPE vmid;
    char uri[1];
}
__attribute__((packed));

int NS_SEND(tellns)(struct shim_ipc_port* port, IDTYPE dest, struct shim_ipc_info* leader,
                    unsigned long seq);
int NS_CALLBACK(tellns)(IPC_CALLBACK_ARGS);

/* LEASE: lease a range of name */
NS_MSG_TYPE(lease) {
    char uri[1];
}
__attribute__((packed));

int NS_SEND(lease)(LEASETYPE* lease);
int NS_CALLBACK(lease)(IPC_CALLBACK_ARGS);

/* OFFER: offer a range of name */
NS_MSG_TYPE(offer) {
    IDTYPE base, size;
    LEASETYPE lease;
};

int NS_SEND(offer)(struct shim_ipc_port* port, IDTYPE dest, IDTYPE base, IDTYPE size,
                   LEASETYPE lease, unsigned long seq);
int NS_CALLBACK(offer)(IPC_CALLBACK_ARGS);

/* RENEW: renew lease of a range of name */
NS_MSG_TYPE(renew) {
    IDTYPE base, size;
}
__attribute__((packed));

int NS_SEND(renew)(IDTYPE base, IDTYPE size);
int NS_CALLBACK(renew)(IPC_CALLBACK_ARGS);

/* SUBLEASE: lease a range of names */
NS_MSG_TYPE(sublease) {
    IDTYPE tenant;
    IDTYPE idx;
    char uri[1];
}
__attribute__((packed));

int NS_SEND(sublease)(IDTYPE tenant, IDTYPE idx, const char* uri, LEASETYPE* lease);
int NS_CALLBACK(sublease)(IPC_CALLBACK_ARGS);

/* QUERY: query the channel of certain name */
NS_MSG_TYPE(query) {
    IDTYPE idx;
}
__attribute__((packed));

int NS_SEND(query)(IDTYPE idx);
int NS_CALLBACK(query)(IPC_CALLBACK_ARGS);

/* QUERY: query the channel of all names */
int NS_SEND(queryall)(void);
int NS_CALLBACK(queryall)(IPC_CALLBACK_ARGS);

/* ANSWER: answer the channel of certain names */
NS_MSG_TYPE(answer) {
    int nanswers;
    struct ipc_ns_offered answers[];
};

int NS_SEND(answer)(struct shim_ipc_port* port, IDTYPE dest, int nanswers,
                    struct ipc_ns_offered* answers, int nowners, struct ipc_ns_client** ownerdata,
                    int* ownerdatasz, unsigned long seq);
int NS_CALLBACK(answer)(IPC_CALLBACK_ARGS);

#ifdef NS_KEY

int CONCAT2(NS, add_key)(NS_KEY* key, IDTYPE id);
int CONCAT2(NS, get_key)(NS_KEY* key, bool delete);

/* FINDKEY */
NS_MSG_TYPE(findkey) {
    NS_KEY key;
};

int NS_SEND(findkey)(NS_KEY* key);
int NS_CALLBACK(findkey)(IPC_CALLBACK_ARGS);

/* TELLKEY */
NS_MSG_TYPE(tellkey) {
    NS_KEY key;
    IDTYPE id;
};

int NS_SEND(tellkey)(struct shim_ipc_port* port, IDTYPE dest, NS_KEY* key, IDTYPE id,
                     unsigned long seq);
int NS_CALLBACK(tellkey)(IPC_CALLBACK_ARGS);

#undef NS_KEY
#endif

IDTYPE CONCAT2(allocate, NS)(IDTYPE min, IDTYPE max);
void CONCAT2(release, NS)(IDTYPE idx);

int CONCAT3(prepare, NS, leader)(void);

#undef NS_SEND
#undef NS_CALLBACK
#undef NS_CODE
#undef NS_MSG_TYPE
#undef NS
#undef NS_CAP
