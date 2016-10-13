/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_UNISTD_H_
#define _SHIM_UNISTD_H_

#ifdef IN_SHIM
#include "shim_types.h"
#else
#include <unistd.h>
#endif

#define __NR_sandbox_create     303
#define __NR_sandbox_attach     304
#define __NR_sandbox_current    305

#define SANDBOX_RPC      0x001
#define SANDBOX_FS       0x002
#define SANDBOX_NET      0x004

struct sockaddr;

struct net_sb_rule {
    int l_addrlen;
    struct sockaddr * l_addr;
    int r_addrlen;
    struct sockaddr * r_addr;
};

struct net_sb {
    int nrules;
    struct net_sb_rule * rules;
};

long sandbox_create (int flags, const char * fs_sb, struct net_sb * net_sb);
int sandbox_attach (unsigned int sbid);
long sandbox_current (void);

#define __NR_msgpersist         306

#define MSGPERSIST_STORE    0
#define MSGPERSIST_LOAD     1
int msgpersist (int msqid, int cmd);

#define __NR_benchmark_rpc      307
#define __NR_send_rpc           308
#define __NR_recv_rpc           309

int benchmark_rpc (pid_t pid, int times, const void * buf, size_t size);

size_t send_rpc (pid_t pid, const void * buf, size_t size);
size_t recv_rpc (pid_t * pid, void * buf, size_t size);

struct nameinfo {
     char * host;
     size_t hostlen;
     char * serv;
     size_t servlen;
};

#define __NR_checkpoint         310

int checkpoint (const char * filename);

struct sigcp {
    int si_session;
};

#define si_cp_session(info) \
    (((struct sigcp *) (info)->_sifields._pad)->si_session)

#define SIGCP                   33

#include "shim_unistd_defs.h"

#endif /* _SHIM_UNISTD_H_ */
