#include <stdbool.h>
#include <stddef.h>

int init_enclave_pages(void);
void* get_enclave_heap_top(void);
void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal);
int free_enclave_pages(void* addr, size_t size);
