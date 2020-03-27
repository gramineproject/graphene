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
    /* `root` points to the root node of the tree or is NULL for an empty tree. */
    struct avl_tree_node* root;
    /* This should be a total order (<=) on tree nodes. If two element compare equal, the newer will
     * be on the left (side of smaller elements) from the older one. */
    bool (*cmp)(struct avl_tree_node*, struct avl_tree_node*);
};

void avl_tree_insert(struct avl_tree* tree, struct avl_tree_node* node);
void avl_tree_delete(struct avl_tree* tree, struct avl_tree_node* node);

/* This function swaps `new_node` in place of `old_node`. `new_node` must not be in any tree (i.e.
 * it should really be a new node) and they both should compare equal with respect to tree.cmp or
 * bad things will happen. You have been warned. */
void avl_tree_swap_node(struct avl_tree_node* old_node, struct avl_tree_node* new_node);

/* These functions return respectively previous and next node or NULL if such does not exist.
 * O(log(n)) in worst case, but amortized O(1) */
struct avl_tree_node* avl_tree_prev(struct avl_tree_node*);
struct avl_tree_node* avl_tree_next(struct avl_tree_node*);

/* Find a node that compares equal to `test_node`. If `tree` has multiple nodes that compare equal,
 * you could get *any* of them.
 * `test_node` does not need to (and usually will not) be in `tree`, it is only passed as
 * an argument to `cmp`. `cmp` is used as a comparison function, so it has to be a total order (to)
 * and for all a, b: cmp(a, b) == tree->cmp(a, b) must hold. */
struct avl_tree_node* avl_tree_find_fn_to(struct avl_tree* tree,
                                          struct avl_tree_node* test_node,
                                          bool cmp(struct avl_tree_node*, struct avl_tree_node*));

/*
 * Similar to `avl_tree_find_fn_to` but with a different signature of `cmp`:
 * cmp(test_node, node) should return:
 * - negative value if test_node < node
 * - zero if test_node == node
 * - positive value if test_node > node
 * It must also be compatible with tree->cmp i.e. (cmp(a, b) <= 0) == tree->cmp(a, b) for all a, b.
 */
struct avl_tree_node* avl_tree_find_fn(struct avl_tree* tree,
                                       void* test_node,
                                       int cmp(void*, struct avl_tree_node*));

/* This is just a shorthand for `avl_tree_find_fn_to(tree, test_node, tree->cmp)` */
struct avl_tree_node* avl_tree_find(struct avl_tree* tree, struct avl_tree_node* test_node);

/* Returns the smallest element in `tree` that is greater or equal to `test_node`, i.e. for which
 * `cmp(test_node, node) <= 0`. Note that if multiple elements compare equal to `test_node`
 * the lately inserted will be returned (the one furthest on the left in the tree).
 * `cmp` must have the same properties as described in `avl_tree_find_fn`. */
struct avl_tree_node* avl_tree_lower_bound(struct avl_tree* tree,
                                           void* test_node,
                                           int cmp(void*, struct avl_tree_node*));

bool debug_avl_tree_is_balanced(struct avl_tree* tree);

#endif // AVL_TREE_H
