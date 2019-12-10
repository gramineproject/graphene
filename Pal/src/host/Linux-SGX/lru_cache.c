#include "lru_cache.h"

DEFINE_LIST(_lruc_list_node);
typedef struct _lruc_list_node {
    LIST_TYPE(_lruc_list_node) list;
    uint64_t key;
} lruc_list_node_t;
DEFINE_LISTP(_lruc_list_node);

typedef struct _lruc_map_node {
    uint64_t key;
	void* data;
	lruc_list_node_t* list_ptr;
    UT_hash_handle hh;
} lruc_map_node_t;

struct lruc_context {
    LISTP_TYPE(_lruc_list_node) list;
    lruc_map_node_t* map;
    lruc_list_node_t* current;
};

#undef uthash_fatal
#define uthash_fatal(msg) lruc_fatal(msg)

void lruc_fatal(const char* msg) {
    SGX_DBG(DBG_E, "%s\n", msg);
    DkProcessExit(-PAL_ERROR_NOMEM);
}

lruc_context_t lruc_create(void) {
    lruc_context_t lruc = malloc(sizeof(struct lruc_context));
    if (!lruc)
        return NULL;

    INIT_LISTP(&lruc->list);
    lruc->map = NULL;
    lruc->current = NULL;
    return lruc;
}

static lruc_map_node_t* get_map_node(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = NULL;
    HASH_FIND(hh, lruc->map, &key, sizeof(key), mn);
    return mn;
}

void lruc_destroy(lruc_context_t lruc) {
    struct _lruc_list_node* ln;
    struct _lruc_list_node* tmp;
    lruc_map_node_t* mn;

    LISTP_FOR_EACH_ENTRY_SAFE(ln, tmp, &lruc->list, list) {
        mn = get_map_node(lruc, ln->key);
        if (mn) {
            HASH_DEL(lruc->map, mn);
            free(mn);
        }
        LISTP_DEL(ln, &lruc->list, list);
        free(ln);
    }

    assert(LISTP_EMPTY(&lruc->list));
    assert(HASH_COUNT(lruc->map) == 0);
    free(lruc);
}

bool lruc_add(lruc_context_t lruc, uint64_t key, void* data) {
    bool ret = false;
    lruc_map_node_t* map_node = malloc(sizeof(*map_node));
    if (!map_node)
        goto out;
    lruc_list_node_t* list_node = malloc(sizeof(*list_node));
    if (!list_node)
        goto out;

    list_node->key = key;
    map_node->key = key;
    LISTP_ADD(list_node, &lruc->list, list);
    lruc_map_node_t* mn = get_map_node(lruc, key);
    assert(mn == NULL);
    map_node->data = data;
    map_node->list_ptr = list_node;
    HASH_ADD(hh, lruc->map, key, sizeof(key), map_node);
    ret = true;
out:
    return ret;
}

void* lruc_find(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = get_map_node(lruc, key);
    if (mn)
        return mn->data;
    return NULL;
}

void* lruc_get(lruc_context_t lruc, uint64_t key) {
    lruc_map_node_t* mn = get_map_node(lruc, key);
    if (!mn)
        return NULL;
    lruc_list_node_t* ln = mn->list_ptr;
    assert(ln != NULL);
    // move node to the front of the list
    LISTP_DEL(ln, &lruc->list, list);
    LISTP_ADD(ln, &lruc->list, list);
    return mn->data;
}

uint32_t lruc_size(lruc_context_t lruc) {
    lruc_list_node_t* ln;
    uint32_t count = 0;
    LISTP_FOR_EACH_ENTRY(ln, &lruc->list, list)
        count++;
    assert(count == HASH_COUNT(lruc->map));
    return count;
}

void* lruc_get_first(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    lruc->current = LISTP_FIRST_ENTRY(&lruc->list, 0, list);
    lruc_map_node_t* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn->data;
}

void* lruc_get_next(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list) || !lruc->current)
        return NULL;

    lruc->current = LISTP_NEXT_ENTRY(lruc->current, &lruc->list, list);
    if (!lruc->current)
        return NULL;

    lruc_map_node_t* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn->data;
}

void* lruc_get_last(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    lruc_list_node_t* ln = LISTP_LAST_ENTRY(&lruc->list, 0, list);
    lruc_map_node_t* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    return mn->data;
}

void lruc_remove_last(lruc_context_t lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return;

    lruc_list_node_t* ln = LISTP_LAST_ENTRY(&lruc->list, 0, list);
    LISTP_DEL(ln, &lruc->list, list);
    free(ln);
    lruc_map_node_t* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    HASH_DEL(lruc->map, mn);
    free(mn);
}

void lruc_test(void) {
    uint64_t a=1, b=2, c=3, d=4;
    SGX_DBG(DBG_D, "\n=== LRUC TEST ===\n");
    lruc_context_t lruc = lruc_create();
    SGX_DBG(DBG_D, "empty size: %u\n", lruc_size(lruc));

    lruc_add(lruc, a, &a);
    SGX_DBG(DBG_D, "after add 1 size: %u\n", lruc_size(lruc));
    uint64_t* x = lruc_find(lruc, a);
    #define X (x?*x:0)
    SGX_DBG(DBG_D, "find(1): %lu\n", X);

    lruc_add(lruc, b, &b);
    SGX_DBG(DBG_D, "after add 2 size: %u\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    SGX_DBG(DBG_D, "find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    SGX_DBG(DBG_D, "find(2): %lu\n", X);

    lruc_add(lruc, c, &c);
    SGX_DBG(DBG_D, "after add 3 size: %u\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    SGX_DBG(DBG_D, "find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    SGX_DBG(DBG_D, "find(2): %lu\n", X);
    x = lruc_find(lruc, c);
    SGX_DBG(DBG_D, "find(3): %lu\n", X);

    lruc_add(lruc, d, &d);
    SGX_DBG(DBG_D, "after add 4 size: %u\n", lruc_size(lruc));
    x = lruc_find(lruc, a);
    SGX_DBG(DBG_D, "find(1): %lu\n", X);
    x = lruc_find(lruc, b);
    SGX_DBG(DBG_D, "find(2): %lu\n", X);
    x = lruc_find(lruc, c);
    SGX_DBG(DBG_D, "find(3): %lu\n", X);
    x = lruc_find(lruc, d);
    SGX_DBG(DBG_D, "find(4): %lu\n", X);

    x = lruc_get(lruc, a);
    SGX_DBG(DBG_D, "after get 1 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, b);
    SGX_DBG(DBG_D, "after get 2 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, c);
    SGX_DBG(DBG_D, "after get 3 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, d);
    SGX_DBG(DBG_D, "after get 4 size: %u, %lu\n", lruc_size(lruc), X);

    lruc_remove_last(lruc);
    x = lruc_get(lruc, a);
    SGX_DBG(DBG_D, "after get 1 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, b);
    SGX_DBG(DBG_D, "after get 2 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, c);
    SGX_DBG(DBG_D, "after get 3 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_get(lruc, d);
    SGX_DBG(DBG_D, "after get 4 size: %u, %lu\n", lruc_size(lruc), X);

    x = lruc_get(lruc, b);
    lruc_remove_last(lruc);
    x = lruc_find(lruc, a);
    SGX_DBG(DBG_D, "after find 1 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, b);
    SGX_DBG(DBG_D, "after find 2 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, c);
    SGX_DBG(DBG_D, "after find 3 size: %u, %lu\n", lruc_size(lruc), X);
    x = lruc_find(lruc, d);
    SGX_DBG(DBG_D, "after find 4 size: %u, %lu\n", lruc_size(lruc), X);
#undef X
    lruc_destroy(lruc);
}
