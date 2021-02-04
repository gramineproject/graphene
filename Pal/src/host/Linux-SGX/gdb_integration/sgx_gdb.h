#include <stdint.h>

#define MAX_DBG_THREADS 1024

/* This address is shared between our GDB and Graphene-SGX and must
 * reside in non-enclave memory. Graphene-SGX puts an enclave_dbginfo
 * object at this address and periodically updates it. Our GDB
 * reads the object from this address to update its internal structs
 * and learn about enclave layout, active threads, etc. */
#define DBGINFO_ADDR 0x100000000000

/* This struct is read using PTRACE_PEEKDATA in 8B increments
 * therefore it is aligned as uint64_t. */
struct __attribute__((aligned(__alignof__(uint64_t)))) enclave_dbginfo {
    int pid;
    uint64_t base;
    uint64_t size;
    uint64_t ssa_frame_size;
    void* aep;
    void* eresume;
    int thread_tids[MAX_DBG_THREADS];
    void* tcs_addrs[MAX_DBG_THREADS];
    uint64_t thread_stepping[MAX_DBG_THREADS / 64]; /* bit vector */
};
