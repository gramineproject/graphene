#include "api.h"
#include "assert.h"
#include "avl_tree.h"
#include "pal.h"
#include "pal_debug.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdnoreturn.h>

noreturn void __abort(void) {
    warn("ABORTED\n");
    DkProcessExit(1);
}

#define EXIT_UNBALANCED() do {                              \
        pal_printf("Unbalanced tree at: %u\n", __LINE__);   \
        DkProcessExit(1);                                   \
    } while(0)

static uint32_t _seed;

static void srand(uint32_t seed) {
    _seed = seed;
}

/* source: https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/rand_r.c */
static int32_t rand(void) {
    int32_t result;

    _seed *= 1103515245;
    _seed += 12345;
    result = (uint32_t)(_seed / 65536) % 2048;

    _seed *= 1103515245;
    _seed += 12345;
    result <<= 10;
    result ^= (uint32_t)(_seed / 65536) % 1024;

    _seed *= 1103515245;
    _seed += 12345;
    result <<= 10;
    result ^= (uint32_t)(_seed / 65536) % 1024;

    return result;
}

struct A {
    struct avl_tree_node node;
    int64_t key;
    bool freed;
};

static bool cmp(struct avl_tree_node* x, struct avl_tree_node* y) {
    return container_of(x, struct A, node)->key <= container_of(y, struct A, node)->key;
}

static int cmp_gen(void* x, struct avl_tree_node* y) {
    return *(int64_t*)x - container_of(y, struct A, node)->key;
}

#define ELEMENTS_COUNT 0x1000
#define RAND_DEL_COUNT 0x100
static struct avl_tree tree = { .root = NULL, .cmp = cmp };
static struct A t[ELEMENTS_COUNT];


__attribute__((unused)) static void debug_print(struct avl_tree_node* node) {
    if (!node) {
        pal_printf("LEAF");
        return;
    }
    pal_printf("%ld (", container_of(node, struct A, node)->key);
    debug_print(node->left);
    pal_printf(") (");
    debug_print(node->right);
    pal_printf(")");
}

static void do_test(int32_t (*get_num)(void)) {
    size_t i;

    for (i = 0; i < ELEMENTS_COUNT; i++) {
        t[i].key = get_num();
        t[i].freed = false;
        avl_tree_insert(&tree, &t[i].node);
        if (!debug_avl_tree_is_balanced(&tree)) {
            EXIT_UNBALANCED();
        }
    }

    static_assert(ELEMENTS_COUNT >= 3, "This code needs at least 3 elements in the tree!");
    struct avl_tree_node* node = tree.root->left;
    while (node->right) {
        node = node->right;
    }

    int64_t val = container_of(node, struct A, node)->key;
    struct avl_tree_node* found_node = avl_tree_lower_bound(&tree, &val, cmp_gen);
    if (!found_node || container_of(found_node, struct A, node)->key != val) {
        pal_printf("avl_tree_lower_bound has not found exisitng node %ld, but returned ", val);
        if (found_node) {
            pal_printf("%ld", container_of(found_node, struct A, node)->key);
        } else {
            pal_printf("NULL");
        }
        pal_printf("\n");
        DkProcessExit(1);
    }

    /* get_num returns int32_t, but tmp.key is a int64_t, so this cannot overflow. */
    struct A tmp = { .key = val + 100 };
    avl_tree_insert(&tree, &tmp.node);
    if (!debug_avl_tree_is_balanced(&tree)) {
        EXIT_UNBALANCED();
    }

    val += 1;
    found_node = avl_tree_lower_bound(&tree, &val, cmp_gen);
    bool found = false;

    /* We can skip the initial node as we increased val. */
    node = avl_tree_next(node);
    while (node) {
        if (node == found_node) {
            found = true;
            break;
        }
        node = avl_tree_next(node);
    }

    /* These two are equivalent, it's just an assert. */
    if (!found || !node) {
        pal_printf("avl_tree_lower_bound has not found the next element!\n");
    }

    avl_tree_delete(&tree, &tmp.node);
    if (!debug_avl_tree_is_balanced(&tree)) {
        EXIT_UNBALANCED();
    }

    i = RAND_DEL_COUNT;
    while (i) {
        uint32_t r = rand() % ELEMENTS_COUNT;
        if (!t[r].freed) {
            t[r].freed = true;
            avl_tree_delete(&tree, &t[r].node);
            --i;
            if (!debug_avl_tree_is_balanced(&tree)) {
                EXIT_UNBALANCED();
            }
        }
    }
    for (i = 0; i < ELEMENTS_COUNT; i++) {
        if (!t[i].freed) {
            avl_tree_delete(&tree, &t[i].node);
            t[i].freed = true;
            if (!debug_avl_tree_is_balanced(&tree)) {
                EXIT_UNBALANCED();
            }
        }
    }
}

static int32_t rand_mod(void) {
    return rand() % 1000;
}

int main(void) {
    pal_printf("Running static tests: ");
    srand(1337);
    do_test(rand_mod);
    do_test(rand);
    pal_printf("Done!\n");

    uint32_t seed = 0;
    if (DkRandomBitsRead(&seed, sizeof(seed)) < 0) {
        pal_printf("\n");
        return 1;
    }
    pal_printf("Running dynamic tests (with seed: %u): ", seed);
    srand(seed);
    do_test(rand_mod);
    do_test(rand);
    pal_printf("Done!\n");

    return 0;
}
