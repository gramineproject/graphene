#include <stddef.h>

int init_enclave_pages(void);
void* get_enclave_pages(void* addr, size_t size);
int free_enclave_pages(void* addr, size_t size);
