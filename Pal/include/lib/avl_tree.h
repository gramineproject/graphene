#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stdbool.h>

struct avl_tree_node {
    struct avl_tree_node* left;
    struct avl_tree_node* right;
    struct avl_tree_node* parent;
    signed char balance; // tree_height(right) - tree_height(left)
};

struct avl_tree {
    struct avl_tree_node* root;
    /* This should be a total order (<=) on tree nodes. */
    bool (*cmp)(struct avl_tree_node*, struct avl_tree_node*);
};

void avl_tree_insert(struct avl_tree* tree, struct avl_tree_node* node);
void avl_tree_delete(struct avl_tree* tree, struct avl_tree_node* node);

/* This function swaps `new_node` in place of `old_node`. `new_node` must not be in any tree (i.e.
 * it should really be a new node) and they both should compare equal with respect to tree.cmp or
 * bad things will happen. You have been warned. */
void avl_tree_swap_node(struct avl_tree_node* old_node, struct avl_tree_node* new_node);

/* These functions return respectively previous and next node or NULL if such does not exist.
 * O(log(n)) in wrost case, but amortized O(1) */
struct avl_tree_node* avl_tree_prev(struct avl_tree_node*);
struct avl_tree_node* avl_tree_next(struct avl_tree_node*);

/* For all a, b: cmp(a, b) == tree->cmp(a, b) should hold. */
struct avl_tree_node* avl_tree_find_fn_to(struct avl_tree* tree,
                                          struct avl_tree_node* test_node,
                                          bool cmp(struct avl_tree_node*, struct avl_tree_node*));

/*
 * cmp(test_node, node) should return:
 * - negative value if test_node < node
 * - zero if test_node == node
 * - positive value if test_node > node
 * It must also be compatible with tree->cmp.
 */
struct avl_tree_node* avl_tree_find_fn(struct avl_tree* tree,
                                       void* test_node,
                                       int cmp(void*, struct avl_tree_node*));

struct avl_tree_node* avl_tree_find(struct avl_tree* tree, struct avl_tree_node* test_node);

struct avl_tree_node* avl_tree_lower_bound(struct avl_tree*,
                                           void*,
                                           int cmp(void*, struct avl_tree_node*));

bool debug_avl_tree_is_balanced(struct avl_tree* tree);

#endif // AVL_TREE_H
