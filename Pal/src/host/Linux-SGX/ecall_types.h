/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

enum {
    ECALL_PAL_MAIN = 0,
    ECALL_THREAD_START,
    ECALL_NR,
};

typedef struct {
    int ms_counter;
    int ms_event;
    void * ms_arg;
} ms_thread_ext_event_t;

struct pal_sec;

typedef struct {
    const char ** ms_arguments;
    const char ** ms_environments;
    void * ms_addr;
    struct pal_sec * ms_sec_info;
    void * ms_enclave_base;
    unsigned long  ms_enclave_size;
} ms_ecall_pal_main_t;

typedef struct {
    void (*ms_func) (void *);
    void * ms_arg;
    unsigned int * ms_child_tid;
    unsigned int ms_tid;
} ms_ecall_thread_start_t;
