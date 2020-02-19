#include <stddef.h>

void init_enclave_pages(void);
void* get_enclave_pages(void* addr, size_t size);
void free_enclave_pages(void* addr, size_t size);
