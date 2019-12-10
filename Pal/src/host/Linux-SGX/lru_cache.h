#ifndef LRU_CACHE_H_
#define LRU_CACHE_H_

#include "pal_internal.h"
#include "pal_linux.h"
#include "uthash.h"

struct lruc_context;
typedef struct lruc_context* lruc_context_t;

lruc_context_t lruc_create(void);
void lruc_destroy(lruc_context_t context);
bool lruc_add(lruc_context_t context, uint64_t key, void* data);
void* lruc_get(lruc_context_t context, uint64_t key);
void* lruc_find(lruc_context_t context, uint64_t key); // only returns the object, do not bump it to the head
uint32_t lruc_size(lruc_context_t context);
void* lruc_get_first(lruc_context_t context);
void* lruc_get_next(lruc_context_t context);
void* lruc_get_last(lruc_context_t context);
void lruc_remove_last(lruc_context_t context);

void lruc_test(void);

#endif /* LRU_CACHE_H_ */
