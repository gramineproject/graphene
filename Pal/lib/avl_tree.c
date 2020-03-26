/* Copyright (C) 2020 Invisible Things Lab
                      Borys Popławski <borysp@invisiblethingslab.com>

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <stddef.h>

#include "assert.h"
#include "avl_tree.h"

static void avl_tree_init_node(struct avl_tree_node* node) {
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->balance = 0;
}

static void avl_tree_insert_unbalanced(struct avl_tree* tree, struct avl_tree_node* node_to_insert) {
    assert(tree);
    assert(tree->root);
    assert(node_to_insert);

    struct avl_tree_node* node = tree->root;

    while (1) {
        if (tree->cmp(node_to_insert, node)) {
            if (!node->left) {
                node->left = node_to_insert;
                node_to_insert->parent = node;
                return;
            } else {
                node = node->left;
            }
        } else {
            if (!node->right) {
                node->right = node_to_insert;
                node_to_insert->parent = node;
                return;
            } else {
                node = node->right;
            }
        }
    }
}

/* Maybe change name to fixup_link? */
static void fixup_parent(struct avl_tree_node* old_node,
                         struct avl_tree_node* new_node,
                         struct avl_tree_node* parent) {
    if (parent) {
        if (parent->left == old_node) {
            parent->left = new_node;
        } else {
            assert(parent->right == old_node);
            parent->right = new_node;
        }
    }

    if (new_node) {
        new_node->parent = parent;
    }
}

static void rot1L(struct avl_tree_node* q, struct avl_tree_node* p) {
    assert(q->parent == p);
    assert(p->right == q);
    assert(q->balance == 1 || q->balance == 0);
    assert(p->balance == 2);

    fixup_parent(p, q, p->parent);

    p->right = q->left;
    if (q->left) {
        q->left->parent = p;
    }

    q->left = p;
    p->parent = q;

    if (q->balance == 1) {
        p->balance = 0;
        q->balance = 0;
    } else { // q->balance == 0
        p->balance = 1;
        q->balance = -1;
    }
}

static void rot1R(struct avl_tree_node* q, struct avl_tree_node* p) {
    assert(q->parent == p);
    assert(p->left == q);
    assert(q->balance == -1 || q->balance == 0);
    assert(p->balance == -2);

    fixup_parent(p, q, p->parent);

    p->left = q->right;
    if (q->right) {
        q->right->parent = p;
    }

    q->right = p;
    p->parent = q;

    if (q->balance == -1) {
        p->balance = 0;
        q->balance = 0;
    } else { // q->balance == 0
        p->balance = -1;
        q->balance = 1;
    }
}

static void rot2RL(struct avl_tree_node* r, struct avl_tree_node* q, struct avl_tree_node* p) {
    assert(q->parent == p);
    assert(p->right == q);
    assert(q->balance == -1);
    assert(p->balance == 2);

    assert(r->parent == q);
    assert(q->left == r);
    assert(-1 <= r->balance && r->balance <= 1);

    fixup_parent(p, r, p->parent);

    p->right = r->left;
    if (r->left) {
        r->left->parent = p;
    }

    q->left = r->right;
    if (r->right) {
        r->right->parent = q;
    }

    r->left = p;
    p->parent = r;

    r->right = q;
    q->parent = r;

    if (r->balance == -1) {
        p->balance = 0;
        q->balance = 1;
    } else if (r->balance == 0) {
        p->balance = 0;
        q->balance = 0;
    } else { // r->balance == 1
        p->balance = -1;
        q->balance = 0;
    }
    r->balance = 0;
}

static void rot2LR(struct avl_tree_node* r, struct avl_tree_node* q, struct avl_tree_node* p) {
    assert(q->parent == p);
    assert(p->left == q);
    assert(q->balance == 1);
    assert(p->balance == -2);

    assert(r->parent == q);
    assert(q->right == r);
    assert(-1 <= r->balance && r->balance <= 1);

    fixup_parent(p, r, p->parent);

    q->right = r->left;
    if (r->left) {
        r->left->parent = q;
    }

    p->left = r->right;
    if (r->right) {
        r->right->parent = p;
    }

    r->left = q;
    q->parent = r;

    r->right = p;
    p->parent = r;

    if (r->balance == -1) {
        q->balance = 0;
        p->balance = 1;
    } else if (r->balance == 0) {
        q->balance = 0;
        p->balance = 0;
    } else { // r->balance == 1
        q->balance = -1;
        p->balance = 0;
    }
    r->balance = 0;
}

/* Returns whether height might have changed. */
static bool avl_tree_do_balance(struct avl_tree_node* node, struct avl_tree_node** new_root_ptr) {
    assert(node->balance == -2 || node->balance == 2);

    struct avl_tree_node* child = NULL;
    bool ret;

    if (node->balance < 0) { // node->balance == -2
        child = node->left;
        if (child->balance == 1) {
            assert(child->right);
            *new_root_ptr = child->right;
            rot2LR(child->right, child, node);
            return true;
        } else { // child->balance <= 0
            *new_root_ptr = child;
            ret = child->balance != 0;
            rot1R(child, node);
            return ret;
        }
    } else { // node->balance == 2
        child = node->right;
        if (child->balance >= 0) {
            *new_root_ptr = child;
            ret = child->balance != 0;
            rot1L(child, node);
            return ret;
        } else { // child->balance == -1
            assert(child->left);
            *new_root_ptr = child->left;
            rot2RL(child->left, child, node);
            return true;
        }
    }
}

enum side {
    LEFT,
    RIGHT
};

/* Returns the root of the sub-tree that balancing stopped at. */
static struct avl_tree_node* avl_tree_balance(struct avl_tree_node* node, enum side side, bool height_increased) {
    assert(node);

    while (1) {
        bool height_changed = true;

        if (side == LEFT) {
            if (height_increased) {
                height_changed = node->balance <= 0;
                node->balance -= 1;
            } else {
                height_changed = node->balance < 0;
                node->balance += 1;
            }
        } else { // side == RIGHT
            assert(side == RIGHT);
            if (height_increased) {
                height_changed = node->balance >= 0;
                node->balance += 1;
            } else {
                height_changed = node->balance > 0;
                node->balance -= 1;
            }
        }

        assert(-2 <= node->balance && node->balance <= 2);
        if (node->balance == -2 || node->balance == 2) {
             height_changed = avl_tree_do_balance(node, &node);
             /* On inserting height never changes. */
             height_changed &= !height_increased;
        }

        /* This sub-tree is balanced, but its height might have changed. */
        if (!height_changed || !node->parent) {
            return node;
        }

        if (node->parent->left == node) {
            side = LEFT;
        } else {
            assert(node->parent->right == node);
            side = RIGHT;
        }
        node = node->parent;
    }
}

void avl_tree_insert(struct avl_tree* tree, struct avl_tree_node* node) {
    avl_tree_init_node(node);

    // inserting into empty tree
    if (!tree->root) {
        tree->root = node;
        return;
    }

    avl_tree_insert_unbalanced(tree, node);

    assert(node->parent);

    struct avl_tree_node* new_root;

    if (node->parent->left == node) {
        new_root = avl_tree_balance(node->parent, LEFT, true);
    } else {
        assert(node->parent->right == node);
        new_root = avl_tree_balance(node->parent, RIGHT, true);
    }

    if (!new_root->parent) {
        tree->root = new_root;
    }
}

void avl_tree_swap_node(struct avl_tree_node* old_node, struct avl_tree_node* new_node) {
    avl_tree_init_node(new_node);

    fixup_parent(old_node, new_node, old_node->parent);

    new_node->left = old_node->left;
    if (new_node->left) {
        new_node->left->parent = new_node;
    }
    new_node->right = old_node->right;
    if (new_node->right) {
        new_node->right->parent = new_node;
    }

    new_node->balance = old_node->balance;
}

struct avl_tree_node* avl_tree_prev(struct avl_tree_node* node) {
    if (node->left) {
        node = node->left;
        while (node->right) {
            node = node->right;
        }
        return node;
    }
    while (node->parent && node->parent->left == node) {
        node = node->parent;
    }
    return node->parent;
}

struct avl_tree_node* avl_tree_next(struct avl_tree_node* node) {
    if (node->right) {
        node = node->right;
        while (node->left) {
            node = node->left;
        }
        return node;
    }
    while (node->parent && node->parent->right == node) {
        node = node->parent;
    }
    return node->parent;
}

void avl_tree_delete(struct avl_tree* tree, struct avl_tree_node* node) {
    if (node->left && node->right) {
        struct avl_tree_node* next = avl_tree_next(node);
        assert(next->balance == 0 || next->balance == 1);
        if (next->right) {
            assert(next->right->balance == 0);
            assert(!next->right->left);
            assert(!next->right->right);
        }
        assert(next->parent);

        struct avl_tree_node* tmp_right = next->right;
        struct avl_tree_node* tmp_parent = next->parent;
        signed char tmp_balance = next->balance;

        fixup_parent(node, next, node->parent);
        /* In this order it works even if both next->left and next->right are NULL pointers,
         * because node->left is not NULL here. */
        fixup_parent(next->left, node->left, next);
        if (next == node->right) {
            next->right = node;
            node->parent = next;
        } else {
            fixup_parent(next->right, node->right, next);
            fixup_parent(next, node, tmp_parent);
        }
        node->left = NULL;
        fixup_parent(node->right, tmp_right, node);

        next->balance = node->balance;
        node->balance = tmp_balance;

        if (tree->root == node) {
            tree->root = next;
        }
    }

    assert(!(node->left && node->right));

    /* This initialization value has no meaning, it's just here to keep gcc happy. */
    enum side side = LEFT;

    if (node->parent) {
        if (node->parent->left == node) {
            side = LEFT;
        } else {
            assert(node->parent->right == node);
            side = RIGHT;
        }
    }

    struct avl_tree_node* new_root = NULL;

    if (!node->left && !node->right) {
        new_root = NULL;
        fixup_parent(node, NULL, node->parent);
    } else if (node->left && !node->right) {
        new_root = node->left;
        fixup_parent(node, node->left, node->parent);
    } else if (!node->left && node->right) {
        new_root = node->right;
        fixup_parent(node, node->right, node->parent);
    }

    if (node->parent) {
        new_root = avl_tree_balance(node->parent, side, false);
    }

    if ((new_root && !new_root->parent) || !node->parent) {
        tree->root = new_root;
    }

    // TODO Needed?
    avl_tree_init_node(node);
}

struct avl_tree_node* avl_tree_find_fn(struct avl_tree* tree,
                                       void* test_node,
                                       int cmp(void*, struct avl_tree_node*)) {
    struct avl_tree_node* node = tree->root;

    while (node) {
        int x = cmp(test_node, node);
        if (x < 0) {
            node = node->left;
        } else if (x == 0) {
            return node;
        } else { // x > 0
            node = node->right;
        }
    }

    return NULL;
}

struct avl_tree_node* avl_tree_find_fn_to(struct avl_tree* tree,
                                          struct avl_tree_node* test_node,
                                          bool cmp(struct avl_tree_node*, struct avl_tree_node*)) {
    struct avl_tree_node* node = tree->root;

    while (node) {
        bool x = cmp(test_node, node);
        if (x) {
            if (cmp(node, test_node)) {
                return node;
            }
            node = node->left;
        } else {
            node = node->right;
        }
    }

    return NULL;
}

struct avl_tree_node* avl_tree_find(struct avl_tree* tree, struct avl_tree_node* node) {
    return avl_tree_find_fn_to(tree, node, tree->cmp);
}

struct avl_tree_node* avl_tree_lower_bound(struct avl_tree* tree,
                                           void* test_node,
                                           int cmp(void*, struct avl_tree_node*)) {
    struct avl_tree_node* node = tree->root;
    struct avl_tree_node* ret = NULL;

    while (node) {
        int x = cmp(test_node, node);
        if (x <= 0) {
            ret = node;
            node = node->left;
        } else { // x > 0
            node = node->right;
        }
    }

    return ret;
}

static bool avl_tree_is_balanced_size(struct avl_tree_node* node, size_t* size) {
    if (!node) {
        *size = 0;
        return true;
    }

    size_t a = 0;
    size_t b = 0;

    bool ret = avl_tree_is_balanced_size(node->left, &a);
    ret &= avl_tree_is_balanced_size(node->right, &b);

    if (a < b) {
        ret &= (b - a) == 1;
        ret &= node->balance == 1;
        *size = b;
    } else if (a == b) {
        ret &= node->balance == 0;
        *size = a;
    } else { // a > b
        ret &= (a - b) == 1;
        ret &= node->balance == -1;
        *size = a;
    }

    *size += 1;
    return ret;
}

bool debug_avl_tree_is_balanced(struct avl_tree* tree) {
    size_t s;
    return avl_tree_is_balanced_size(tree->root, &s);
}
