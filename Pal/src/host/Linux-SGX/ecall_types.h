/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_NR,
};

struct pal_sec;

typedef struct {
    char * ms_args;
    uint64_t ms_args_size;
    char * ms_env;
    uint64_t ms_env_size;
    struct pal_sec * ms_sec_info;
} ms_ecall_enclave_start_t;
