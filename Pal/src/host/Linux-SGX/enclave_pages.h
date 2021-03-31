#include <stdbool.h>
#include <stddef.h>

typedef enum {
    HEAP = 0,
    STACK,
    MEMORY_SEG_MAX,
} SGX_MEMORY_SEG;

struct sgx_eaug_range_param {
    SGX_MEMORY_SEG mem_seg;
    unsigned int num_pages;
    unsigned long fault_addr;
};

int init_enclave_pages(void);
void* get_enclave_heap_top(void);
void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal);
int free_enclave_pages(void* addr, size_t size);
