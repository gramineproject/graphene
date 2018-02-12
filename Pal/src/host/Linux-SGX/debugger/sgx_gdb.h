/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define MAX_DBG_THREADS     64

struct enclave_dbginfo {
    int                 pid;
    unsigned long       base, size;
    unsigned long       ssaframesize;
    void *              aep;
    int                 thread_tids[MAX_DBG_THREADS];
    void *              tcs_addrs[MAX_DBG_THREADS];
    unsigned long long  thread_stepping;
};

#define DBGINFO_ADDR        0x100000000000
