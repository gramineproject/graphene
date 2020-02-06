#ifndef _SHIM_UNISTD_H_
#define _SHIM_UNISTD_H_

#ifdef IN_SHIM
#include "shim_types.h"
#else
/* XXX(borysp): This is hacky. Normally we would want to just include <sys/types.h> but it would
 * break some tests in "inline" directory. The main reason is that other header files are not
 * prepared for being included both in LibOS and in standalone binaries. Fortunately this header
 * only missed one type definition, hence this typedef suffices. */
typedef int pid_t;
#include <unistd.h>
#endif

#define __NR_msgpersist (LIBOS_SYSCALL_BASE + 1)

#define MSGPERSIST_STORE 0
#define MSGPERSIST_LOAD  1
int msgpersist(int msqid, int cmd);

#define __NR_benchmark_rpc (LIBOS_SYSCALL_BASE + 2)
#define __NR_send_rpc      (LIBOS_SYSCALL_BASE + 3)
#define __NR_recv_rpc      (LIBOS_SYSCALL_BASE + 4)

int benchmark_rpc(pid_t pid, int times, const void* buf, size_t size);

size_t send_rpc(pid_t pid, const void* buf, size_t size);
size_t recv_rpc(pid_t* pid, void* buf, size_t size);

struct nameinfo {
    char* host;
    size_t hostlen;
    char* serv;
    size_t servlen;
};

#define __NR_checkpoint (LIBOS_SYSCALL_BASE + 5)

int checkpoint(const char* filename);

struct sigcp {
    int si_session;
};

#define SI_CP_SESSION(info) (((struct sigcp*)&(info)->_sifields)->si_session)

#define SIGCP 33

#include "shim_unistd_defs.h"

#endif /* _SHIM_UNISTD_H_ */
