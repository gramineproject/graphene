#ifndef SGX_ENCLAVE_H_
#define SGX_ENCLAVE_H_

#include <stddef.h>
#include "sgx_tls.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env, size_t env_size,
                        struct ocall_args* ocall_args_ptr);

void ecall_thread_start(struct ocall_args* ocall_args_ptr);

#endif // SGX_ENCLAVE_H_
