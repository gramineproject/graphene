enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_NR,
};

struct pal_sec;

typedef struct {
    char * ms_args;
    size_t ms_args_size;
    char * ms_env;
    size_t ms_env_size;
    struct pal_sec * ms_sec_info;
} ms_ecall_enclave_start_t;
