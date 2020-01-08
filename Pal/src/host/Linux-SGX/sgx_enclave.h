#include "pal_linux.h"
#include "pal_security.h"

int ecall_enclave_start(char* args, size_t args_size, char* env, size_t env_size);

int ecall_thread_start(void);

int ecall_thread_reset(void);
