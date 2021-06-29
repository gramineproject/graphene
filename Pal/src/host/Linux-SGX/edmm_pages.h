#ifndef EDMM_PAGES_H
#define EDMM_PAGES_H

#include "pal_linux.h"

/* TODO: Setting this as 64 to start with, but will need to revisit */
#define EDMM_HEAP_RANGE_CNT 64

/* edmm_heap_range objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_EDMM_HEAP_RANGE 10000

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

DEFINE_LIST(edmm_heap_pool);
DEFINE_LISTP(edmm_heap_pool);
struct edmm_heap_pool {
    LIST_TYPE(edmm_heap_pool) list;
    void* addr;
    size_t size;
};

size_t find_preallocated_heap_nonoverlap(void* addr, size_t size);
int free_edmm_page_range(void* start, size_t size);
int get_edmm_page_range(void* start, size_t size, bool executable);
int add_to_pending_free_epc(void* addr, size_t size);
int remove_from_pending_free_epc(void* addr, size_t size,
                                 struct edmm_heap_pool* updated_heap_alloc);

#endif /* EDMM_PAGES_H */