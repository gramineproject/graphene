/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_NR,
};

struct pal_sec;

typedef struct {
    const char ** ms_arguments;
    const char ** ms_environments;
    struct pal_sec * ms_sec_info;
} ms_ecall_enclave_start_t;
