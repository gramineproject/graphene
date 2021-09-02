/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */

#include <linux/fcntl.h>
#include <linux/mman.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "avl_tree.h"
#include "shim_checkpoint.h"
#include "shim_defs.h"
#include "shim_flags_conv.h"
/* TODO: remove the include of "shim_fs.h" once the circular dependency of it and "shim_handle.h"
 * is fixed. */
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_tcb.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "spinlock.h"

/* Filter flags that will be saved in `struct shim_vma`. For example there is no need for saving
 * MAP_FIXED or unsupported flags. */
static int filter_saved_flags(int flags) {
    return flags & (MAP_SHARED | MAP_SHARED_VALIDATE | MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN
                    | MAP_HUGETLB | MAP_HUGE_2MB | MAP_HUGE_1GB | MAP_STACK
                    | VMA_UNMAPPED | VMA_INTERNAL | VMA_TAINTED);
}

/* TODO: split flags into internal (Graphene) and Linux; also to consider: completely remove Linux
 * flags - we only need MAP_SHARED/MAP_PRIVATE and possibly MAP_STACK/MAP_GROWSDOWN */
struct shim_vma {
    uintptr_t begin;
    uintptr_t end;
    int prot;
    int flags;
    struct shim_handle* file;
    uint64_t offset; // offset inside `file`, where `begin` starts
    union {
        /* If this `vma` is used, it is included in `vma_tree` using this node. */
        struct avl_tree_node tree_node;
        /* Otherwise it might be cached in per thread vma cache, or might be on a temporary list
         * of to-be-freed vmas (used by _vma_bkeep_remove). Such lists use the field below. */
        struct shim_vma* next_free;
    };
    char comment[VMA_COMMENT_LEN];
};

static void copy_comment(struct shim_vma* vma, const char* comment) {
    size_t size = MIN(sizeof(vma->comment), strlen(comment) + 1);
    memcpy(vma->comment, comment, size);
    vma->comment[sizeof(vma->comment) - 1] = '\0';
}

static void copy_vma(struct shim_vma* old_vma, struct shim_vma* new_vma) {
    new_vma->begin = old_vma->begin;
    new_vma->end   = old_vma->end;
    new_vma->prot  = old_vma->prot;
    new_vma->flags = old_vma->flags;
    new_vma->file  = old_vma->file;
    if (new_vma->file) {
        get_handle(new_vma->file);
    }
    new_vma->offset = old_vma->offset;
    copy_comment(new_vma, old_vma->comment);
}

static bool vma_tree_cmp(struct avl_tree_node* node_a, struct avl_tree_node* node_b) {
    struct shim_vma* a = container_of(node_a, struct shim_vma, tree_node);
    struct shim_vma* b = container_of(node_b, struct shim_vma, tree_node);

    return a->end <= b->end;
}

static bool is_addr_in_vma(uintptr_t addr, struct shim_vma* vma) {
    return vma->begin <= addr && addr < vma->end;
}

/* Returns whether `addr` is smaller or inside a vma (`node`). */
static bool cmp_addr_to_vma(void* addr, struct avl_tree_node* node) {
    struct shim_vma* vma = container_of(node, struct shim_vma, tree_node);

    return (uintptr_t)addr < vma->end;
}

/*
 * "vma_tree" holds all vmas with the assumption that no 2 overlap (though they could be adjacent).
 * Currently we do not merge similar adjacent vmas - if we ever start doing it, this code needs
 * to be revisited as there might be some optimizations that would break due to it.
 */
static struct avl_tree vma_tree = {.cmp = vma_tree_cmp};
static spinlock_t vma_tree_lock = INIT_SPINLOCK_UNLOCKED;

static struct shim_vma* node2vma(struct avl_tree_node* node) {
    if (!node) {
        return NULL;
    }
    return container_of(node, struct shim_vma, tree_node);
}

static struct shim_vma* _get_next_vma(struct shim_vma* vma) {
    assert(spinlock_is_locked(&vma_tree_lock));
    return node2vma(avl_tree_next(&vma->tree_node));
}

static struct shim_vma* _get_prev_vma(struct shim_vma* vma) {
    assert(spinlock_is_locked(&vma_tree_lock));
    return node2vma(avl_tree_prev(&vma->tree_node));
}

static struct shim_vma* _get_last_vma(void) {
    assert(spinlock_is_locked(&vma_tree_lock));
    return node2vma(avl_tree_last(&vma_tree));
}

static struct shim_vma* _get_first_vma(void) {
    assert(spinlock_is_locked(&vma_tree_lock));
    return node2vma(avl_tree_first(&vma_tree));
}

/* Returns the vma that contains `addr`. If there is no such vma, returns the closest vma with
 * higher address. */
static struct shim_vma* _lookup_vma(uintptr_t addr) {
    assert(spinlock_is_locked(&vma_tree_lock));

    struct avl_tree_node* node = avl_tree_lower_bound_fn(&vma_tree, (void*)addr, cmp_addr_to_vma);
    if (!node) {
        return NULL;
    }
    return container_of(node, struct shim_vma, tree_node);
}

typedef bool (*traverse_visitor)(struct shim_vma* vma, void* visitor_arg);

/*
 * Walks through all VMAs which contain at least one byte from the [begin, end) range.
 *
 * `visitor` returns whether to continue iteration. It must be as simple as possible, because
 * it's called with the VMA lock held.
 *
 * Returns whether the traversed range was continuously covered by VMAs. This is useful for
 * emulating errors in memory management syscalls.
 */
// TODO: Probably other VMA functions could make use of this helper.
static bool _traverse_vmas_in_range(uintptr_t begin, uintptr_t end, traverse_visitor visitor,
                                    void* visitor_arg) {
    assert(spinlock_is_locked(&vma_tree_lock));
    assert(begin <= end);

    if (begin == end)
        return true;

    struct shim_vma* vma = _lookup_vma(begin);
    if (!vma || end <= vma->begin)
        return false;

    struct shim_vma* prev = NULL;
    bool is_continuous = vma->begin <= begin;

    while (1) {
        if (!visitor(vma, visitor_arg))
            break;

        prev = vma;
        vma = _get_next_vma(vma);
        if (!vma || end <= vma->begin) {
            is_continuous &= end <= prev->end;
            break;
        }

        is_continuous &= prev->end == vma->begin;
    }

    return is_continuous;
}

static void split_vma(struct shim_vma* old_vma, struct shim_vma* new_vma, uintptr_t addr) {
    assert(old_vma->begin < addr && addr < old_vma->end);

    copy_vma(old_vma, new_vma);
    new_vma->begin = addr;
    if (new_vma->file) {
        new_vma->offset += new_vma->begin - old_vma->begin;
    }

    old_vma->end = addr;
}

/*
 * This function might need a preallocated vma in `new_vma_ptr`, because it might need to split
 * an existing vma into two parts. If the vma is provided and this function happens to use it,
 * `*new_vma_ptr` will be set to NULL.
 * It returns a list of vmas that need to be freed in `vmas_to_free`.
 * Range [begin, end) can consist of multiple vmas even with holes in between, but they all must be
 * either internal or non-internal.
 */
static int _vma_bkeep_remove(uintptr_t begin, uintptr_t end, bool is_internal,
                             struct shim_vma** new_vma_ptr, struct shim_vma** vmas_to_free) {
    assert(spinlock_is_locked(&vma_tree_lock));
    assert(!new_vma_ptr || *new_vma_ptr);
    assert(IS_ALLOC_ALIGNED_PTR(begin) && IS_ALLOC_ALIGNED_PTR(end));

    struct shim_vma* vma = _lookup_vma(begin);
    if (!vma) {
        return 0;
    }

    struct shim_vma* first_vma = vma;

    while (vma && vma->begin < end) {
        if (!!(vma->flags & VMA_INTERNAL) != is_internal) {
            if (is_internal) {
                log_warning("LibOS tried to free a user vma!");
            } else {
                log_warning("user app tried to free an internal vma!");
            }
            return -EACCES;
        }

        vma = _get_next_vma(vma);
    }

    vma = first_vma;

    if (vma->begin < begin) {
        if (end < vma->end) {
            if (!new_vma_ptr) {
                log_warning("need an additional vma to free this range!");
                return -ENOMEM;
            }
            struct shim_vma* new_vma = *new_vma_ptr;
            *new_vma_ptr = NULL;

            split_vma(vma, new_vma, end);
            vma->end = begin;

            avl_tree_insert(&vma_tree, &new_vma->tree_node);
            return 0;
        }

        vma->end = begin;

        vma = _get_next_vma(vma);
        if (!vma) {
            return 0;
        }
    }

    while (vma->end <= end) {
        /* We need to search for the next node before deletion. */
        struct shim_vma* next = _get_next_vma(vma);

        avl_tree_delete(&vma_tree, &vma->tree_node);

        vma->next_free = NULL;
        *vmas_to_free = vma;
        vmas_to_free = &vma->next_free;

        if (!next) {
            return 0;
        }
        vma = next;
    }

    if (vma->begin < end) {
        if (vma->file) {
            vma->offset += end - vma->begin;
        }
        vma->begin = end;
    }

    return 0;
}

static void free_vmas_freelist(struct shim_vma* vma);

/* This function uses at most 1 vma (in `bkeep_mmap_any`). `alloc_vma` depends on this behavior. */
static void* _vma_malloc(size_t size) {
    void* addr = NULL;
    size = ALLOC_ALIGN_UP(size);

    if (bkeep_mmap_any(size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL,
                       NULL, 0, "vma", &addr) < 0) {
        return NULL;
    }

    int ret = DkVirtualMemoryAlloc(&addr, size, 0, PAL_PROT_WRITE | PAL_PROT_READ);
    if (ret < 0) {
        struct shim_vma* vmas_to_free = NULL;

        spinlock_lock(&vma_tree_lock);
        /* Since we are freeing a range we just created, additional vma is not needed. */
        ret = _vma_bkeep_remove((uintptr_t)addr, (uintptr_t)addr + size, /*is_internal=*/true, NULL,
                                &vmas_to_free);
        spinlock_unlock(&vma_tree_lock);
        if (ret < 0) {
            log_error("Removing a vma we just created failed with %d!", ret);
            BUG();
        }

        free_vmas_freelist(vmas_to_free);
        return NULL;
    }

    return addr;
}

/* We never free `vma_mgr`. */
static void _vma_free(void* ptr, size_t size) {
    __UNUSED(ptr);
    __UNUSED(size);
    BUG();
}

#undef system_malloc
#undef system_free
#define system_malloc _vma_malloc
#define system_free   _vma_free
#define OBJ_TYPE      struct shim_vma
#include "memmgr.h"

static struct shim_lock vma_mgr_lock;
static MEM_MGR vma_mgr = NULL;

/*
 * We use a following per-thread caching mechanism of VMAs:
 * Each thread has a singly linked list of free VMAs, with maximal length of 3.
 * Allocation first checks if there is a cached VMA, deallocation adds it to cache, unless it is
 * full (3 entries already present).
 * Note that 3 is configurable number as long as it is a power of 2 minus 1 and `struct shim_vma`
 * alignment is not less that it. This is needed for storing the list length in lower bits of
 * the pointer (small optimization not to add more fields to TCB - can be removed if the max list
 * size needs to be increased or any supported architecture does not allow for it).
 */
#ifndef __x86_64__
/* If this optimization will work on the architecture you port Graphene to, add it to the check
 * above. */
#error "This optimization requires specific representation of pointers."
#endif

#define VMA_CACHE_SIZE 3ull
static_assert((VMA_CACHE_SIZE & (VMA_CACHE_SIZE + 1)) == 0,
              "VMA_CACHE_SIZE must be a power of 2 minus 1!");

static struct shim_vma* cache2ptr(void* vma) {
    static_assert(
        alignof(struct shim_vma) >= VMA_CACHE_SIZE + 1,
        "We need some lower bits of pointers to `struct shim_vma` for this optimization!");
    return (struct shim_vma*)((uintptr_t)vma & ~VMA_CACHE_SIZE);
}

static void* create_cache_ptr(struct shim_vma* vma, size_t size) {
    assert(size <= VMA_CACHE_SIZE);
    return (void*)((uintptr_t)vma | size);
}

static size_t cache2size(void* vma) {
    return (size_t)((uintptr_t)vma & VMA_CACHE_SIZE);
}

static struct shim_vma* get_from_thread_vma_cache(void) {
    struct shim_vma* vma = cache2ptr(SHIM_TCB_GET(vma_cache));
    if (!vma) {
        return NULL;
    }
    SHIM_TCB_SET(vma_cache, vma->next_free);
    return vma;
}

static bool add_to_thread_vma_cache(struct shim_vma* vma) {
    assert(cache2size(vma) == 0);
    void* ptr = SHIM_TCB_GET(vma_cache);
    size_t size = cache2size(ptr);

    if (size >= VMA_CACHE_SIZE) {
        return false;
    }

    vma->next_free = ptr;
    SHIM_TCB_SET(vma_cache, create_cache_ptr(vma, size + 1));
    return true;
}

static void remove_from_thread_vma_cache(struct shim_vma* to_remove) {
    assert(to_remove);

    struct shim_vma* first_vma = cache2ptr(SHIM_TCB_GET(vma_cache));

    if (first_vma == to_remove) {
        SHIM_TCB_SET(vma_cache, first_vma->next_free);
        return;
    }

    struct shim_vma* vma = first_vma;
    bool found = false;
    while (vma) {
        struct shim_vma* next = cache2ptr(vma->next_free);
        if (next == to_remove) {
            found = true;
            break;
        }
        vma = next;
    }
    if (!found) {
        return;
    }

    SHIM_TCB_SET(vma_cache, create_cache_ptr(first_vma, cache2size(first_vma) - 1));
    vma = first_vma;
    while (vma) {
        struct shim_vma* next = cache2ptr(vma->next_free);
        if (next == to_remove) {
            vma->next_free = next->next_free;
            return;
        }
        vma->next_free = create_cache_ptr(next, cache2size(vma->next_free) - 1);
        vma = next;
    }
}

static struct shim_vma* alloc_vma(void) {
    struct shim_vma* vma = get_from_thread_vma_cache();
    if (vma) {
        goto out;
    }

    lock(&vma_mgr_lock);
    vma = get_mem_obj_from_mgr(vma_mgr);
    if (!vma) {
        /* `enlarge_mem_mgr` below will call _vma_malloc, which uses at most 1 vma - so we
         * temporarily provide it. */
        struct shim_vma tmp_vma = {0};
        /* vma cache is empty, as we checked it before. */
        if (!add_to_thread_vma_cache(&tmp_vma)) {
            log_error("Failed to add tmp vma to cache!");
            BUG();
        }
        if (!enlarge_mem_mgr(vma_mgr, size_align_up(DEFAULT_VMA_COUNT))) {
            remove_from_thread_vma_cache(&tmp_vma);
            goto out_unlock;
        }

        struct shim_vma* vma_migrate = get_mem_obj_from_mgr(vma_mgr);
        if (!vma_migrate) {
            log_error("Failed to allocate a vma right after enlarge_mem_mgr!");
            BUG();
        }

        spinlock_lock(&vma_tree_lock);
        /* Currently `tmp_vma` is always used (added to `vma_tree`), but this assumption could
         * easily be changed (e.g. if we implement VMAs merging).*/
        struct avl_tree_node* node = &tmp_vma.tree_node;
        if (node->parent || vma_tree.root == node) {
            /* `tmp_vma` is in `vma_tree`, we need to migrate it. */
            copy_vma(&tmp_vma, vma_migrate);
            avl_tree_swap_node(&vma_tree, node, &vma_migrate->tree_node);
            vma_migrate = NULL;
        }
        spinlock_unlock(&vma_tree_lock);

        if (vma_migrate) {
            free_mem_obj_to_mgr(vma_mgr, vma_migrate);
        }
        remove_from_thread_vma_cache(&tmp_vma);

        vma = get_mem_obj_from_mgr(vma_mgr);
    }

out_unlock:
    unlock(&vma_mgr_lock);
out:
    if (vma) {
        memset(vma, 0, sizeof(*vma));
    }
    return vma;
}

static void free_vma(struct shim_vma* vma) {
    if (vma->file) {
        put_handle(vma->file);
    }

    if (add_to_thread_vma_cache(vma)) {
        return;
    }

    lock(&vma_mgr_lock);
    free_mem_obj_to_mgr(vma_mgr, vma);
    unlock(&vma_mgr_lock);
}

static void free_vmas_freelist(struct shim_vma* vma) {
    while (vma) {
        struct shim_vma* next = vma->next_free;
        free_vma(vma);
        vma = next;
    }
}

static int _bkeep_initial_vma(struct shim_vma* new_vma) {
    assert(spinlock_is_locked(&vma_tree_lock));

    struct shim_vma* tmp_vma = _lookup_vma(new_vma->begin);
    if (tmp_vma && tmp_vma->begin < new_vma->end) {
        return -EEXIST;
    } else {
        avl_tree_insert(&vma_tree, &new_vma->tree_node);
        return 0;
    }
}

#define ASLR_BITS 12
/* This variable is written to only once, during initialization, so it does not need to
 * be atomic. */
static void* g_aslr_addr_top = NULL;

int init_vma(void) {
    struct shim_vma init_vmas[2 + g_pal_control->preloaded_ranges_cnt];

    init_vmas[0].begin = 0; // vma for creation of memory manager

    init_vmas[1].begin  = (uintptr_t)&__load_address;
    init_vmas[1].end    = (uintptr_t)ALLOC_ALIGN_UP_PTR(&__load_address_end);
    init_vmas[1].prot   = PROT_NONE;
    init_vmas[1].flags  = MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL;
    init_vmas[1].file   = NULL;
    init_vmas[1].offset = 0;
    copy_comment(&init_vmas[1], "LibOS");

    for (size_t i = 0; i < g_pal_control->preloaded_ranges_cnt; i++) {
        init_vmas[2 + i].begin  = ALLOC_ALIGN_DOWN(g_pal_control->preloaded_ranges[i].start);
        init_vmas[2 + i].end    = ALLOC_ALIGN_UP(g_pal_control->preloaded_ranges[i].end);
        init_vmas[2 + i].prot   = PROT_NONE;
        init_vmas[2 + i].flags  = MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL;
        init_vmas[2 + i].file   = NULL;
        init_vmas[2 + i].offset = 0;
        copy_comment(&init_vmas[2 + i], g_pal_control->preloaded_ranges[i].comment);
    }

    spinlock_lock(&vma_tree_lock);
    int ret = 0;
    /* First of init_vmas is reserved for later usage. */
    for (size_t i = 1; i < ARRAY_SIZE(init_vmas); i++) {
        assert(init_vmas[i].begin <= init_vmas[i].end);
        /* Skip empty areas. */
        if (init_vmas[i].begin == init_vmas[i].end) {
            log_debug("Skipping bookkeeping of empty region at 0x%lx (comment: \"%s\")",
                      init_vmas[i].begin, init_vmas[i].comment);
            continue;
        }
        if (!IS_ALLOC_ALIGNED(init_vmas[i].begin) || !IS_ALLOC_ALIGNED(init_vmas[i].end)) {
            log_error("Unaligned VMA region: 0x%lx-0x%lx (%s)", init_vmas[i].begin,
                      init_vmas[i].end, init_vmas[i].comment);
            ret = -EINVAL;
            break;
        }
        ret = _bkeep_initial_vma(&init_vmas[i]);
        if (ret < 0) {
            log_error("Failed to bookkeep initial VMA region 0x%lx-0x%lx (%s)",
                      init_vmas[i].begin, init_vmas[i].end, init_vmas[i].comment);
            break;
        }
        log_debug("Initial VMA region 0x%lx-0x%lx (%s) bookkeeped", init_vmas[i].begin,
                  init_vmas[i].end, init_vmas[i].comment);
    }
    spinlock_unlock(&vma_tree_lock);
    /* From now on if we return with an error we might leave a structure local to this function in
     * vma_tree. We do not bother with removing them - this is initialization of VMA subsystem, if
     * it fails the whole application startup fails and we should never call any of functions in
     * this file. */
    if (ret < 0) {
        return ret;
    }

    g_aslr_addr_top = g_pal_control->user_address.end;

    if (!g_pal_control->disable_aslr) {
        /* Inspired by: https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/mm/mmap.c#L80 */
        size_t gap_max_size =
            (g_pal_control->user_address.end - g_pal_control->user_address.start) / 6 * 5;
        /* We do address space randomization only if we have at least ASLR_BITS to randomize. */
        if (gap_max_size / ALLOC_ALIGNMENT >= (1ul << ASLR_BITS)) {
            size_t gap = 0;

            int ret = DkRandomBitsRead(&gap, sizeof(gap));
            if (ret < 0) {
                return pal_to_unix_errno(ret);
            }

            /* Resulting distribution is not ideal, but it should not be an issue here. */
            gap = ALLOC_ALIGN_DOWN(gap % gap_max_size);
            g_aslr_addr_top = (char*)g_aslr_addr_top - gap;

            log_debug("ASLR top address adjusted to %p", g_aslr_addr_top);
        } else {
            log_warning("Not enough space to make meaningful address space randomization.");
        }
    }

    /* We need 1 vma to create the memmgr. */
    if (!add_to_thread_vma_cache(&init_vmas[0])) {
        log_error("Failed to add tmp vma to cache!");
        BUG();
    }
    vma_mgr = create_mem_mgr(DEFAULT_VMA_COUNT);
    if (!vma_mgr) {
        log_error("Failed to create VMA memory manager!");
        return -ENOMEM;
    }

    if (!create_lock(&vma_mgr_lock)) {
        return -ENOMEM;
    }

    /* Now we need to migrate temporary initial vmas. */
    struct shim_vma* vmas_to_migrate_to[ARRAY_SIZE(init_vmas)];
    for (size_t i = 0; i < ARRAY_SIZE(vmas_to_migrate_to); i++) {
        vmas_to_migrate_to[i] = alloc_vma();
        if (!vmas_to_migrate_to[i]) {
            return -ENOMEM;
        }
    }

    spinlock_lock(&vma_tree_lock);
    for (size_t i = 0; i < ARRAY_SIZE(init_vmas); i++) {
        /* Skip empty areas. */
        if (init_vmas[i].begin == init_vmas[i].end) {
            continue;
        }
        copy_vma(&init_vmas[i], vmas_to_migrate_to[i]);
        avl_tree_swap_node(&vma_tree, &init_vmas[i].tree_node, &vmas_to_migrate_to[i]->tree_node);
        vmas_to_migrate_to[i] = NULL;
    }
    spinlock_unlock(&vma_tree_lock);

    for (size_t i = 0; i < ARRAY_SIZE(vmas_to_migrate_to); i++) {
        if (vmas_to_migrate_to[i]) {
            free_vma(vmas_to_migrate_to[i]);
        }
    }

    return 0;
}

static void _add_unmapped_vma(uintptr_t begin, uintptr_t end, struct shim_vma* vma) {
    assert(spinlock_is_locked(&vma_tree_lock));

    vma->begin  = begin;
    vma->end    = end;
    vma->prot   = PROT_NONE;
    vma->flags  = VMA_INTERNAL | VMA_UNMAPPED;
    vma->file   = NULL;
    vma->offset = 0;
    copy_comment(vma, "");

    avl_tree_insert(&vma_tree, &vma->tree_node);
}

// TODO change so that vma1 is provided by caller
int bkeep_munmap(void* addr, size_t length, bool is_internal, void** tmp_vma_ptr) {
    assert(tmp_vma_ptr);

    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct shim_vma* vma1 = alloc_vma();
    if (!vma1) {
        return -ENOMEM;
    }
    /* Unmapping may succeed even without this vma, so if this allocation fails we move on. */
    struct shim_vma* vma2 = alloc_vma();

    struct shim_vma* vmas_to_free = NULL;

    spinlock_lock(&vma_tree_lock);
    int ret = _vma_bkeep_remove((uintptr_t)addr, (uintptr_t)addr + length, is_internal,
                                vma2 ? &vma2 : NULL, &vmas_to_free);
    if (ret >= 0) {
        _add_unmapped_vma((uintptr_t)addr, (uintptr_t)addr + length, vma1);
        *tmp_vma_ptr = (void*)vma1;
        vma1 = NULL;
    }
    spinlock_unlock(&vma_tree_lock);

    free_vmas_freelist(vmas_to_free);
    if (vma1) {
        free_vma(vma1);
    }
    if (vma2) {
        free_vma(vma2);
    }

    /*
     * TODO: We call `remove_r_debug()` on the assumption that `addr` might be the beginning of a
     * loaded ELF object. However, `remove_r_debug()` assumes that `addr` is the load base, while
     * the first mapping of an ELF object might begin later than its load base.
     */
    remove_r_debug(addr);
    return ret;
}

void bkeep_remove_tmp_vma(void* _vma) {
    struct shim_vma* vma = (struct shim_vma*)_vma;

    assert(vma->flags == (VMA_INTERNAL | VMA_UNMAPPED));

    spinlock_lock(&vma_tree_lock);
    avl_tree_delete(&vma_tree, &vma->tree_node);
    spinlock_unlock(&vma_tree_lock);

    free_vma(vma);
}

static bool is_file_prot_matching(struct shim_handle* file_hdl, int prot) {
    return !(prot & PROT_WRITE) || (file_hdl->flags & O_RDWR);
}

int bkeep_mmap_fixed(void* addr, size_t length, int prot, int flags, struct shim_handle* file,
                     uint64_t offset, const char* comment) {
    assert(flags & (MAP_FIXED | MAP_FIXED_NOREPLACE));

    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct shim_vma* new_vma = alloc_vma();
    if (!new_vma) {
        return -ENOMEM;
    }
    /* Unmapping may succeed even without this vma, so if this allocation fails we move on. */
    struct shim_vma* vma1 = alloc_vma();

    new_vma->begin = (uintptr_t)addr;
    new_vma->end   = new_vma->begin + length;
    new_vma->prot  = prot;
    new_vma->flags = filter_saved_flags(flags) | ((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    new_vma->file  = file;
    if (new_vma->file) {
        get_handle(new_vma->file);
    }
    new_vma->offset = file ? offset : 0;
    copy_comment(new_vma, comment ?: "");

    struct shim_vma* vmas_to_free = NULL;

    spinlock_lock(&vma_tree_lock);
    int ret = 0;
    if (flags & MAP_FIXED_NOREPLACE) {
        struct shim_vma* tmp_vma = _lookup_vma(new_vma->begin);
        if (tmp_vma && tmp_vma->begin < new_vma->end) {
            ret = -EEXIST;
        }
    } else {
        ret = _vma_bkeep_remove(new_vma->begin, new_vma->end, !!(flags & VMA_INTERNAL),
                                vma1 ? &vma1 : NULL, &vmas_to_free);
    }
    if (ret >= 0) {
        avl_tree_insert(&vma_tree, &new_vma->tree_node);
    }
    spinlock_unlock(&vma_tree_lock);

    free_vmas_freelist(vmas_to_free);
    if (vma1) {
        free_vma(vma1);
    }

    if (ret < 0) {
        free_vma(new_vma);
    }
    return ret;
}

static void vma_update_prot(struct shim_vma* vma, int prot) {
    vma->prot = prot & (PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC);
    if (vma->file && (prot & PROT_WRITE)) {
        vma->flags |= VMA_TAINTED;
    }
}

static int _vma_bkeep_change(uintptr_t begin, uintptr_t end, int prot, bool is_internal,
                             struct shim_vma** new_vma_ptr1, struct shim_vma** new_vma_ptr2) {
    assert(spinlock_is_locked(&vma_tree_lock));
    assert(IS_ALLOC_ALIGNED_PTR(begin) && IS_ALLOC_ALIGNED_PTR(end));
    assert(begin < end);

    struct shim_vma* vma = _lookup_vma(begin);
    if (!vma) {
        return -ENOMEM;
    }

    struct shim_vma* prev = NULL;
    struct shim_vma* first_vma = vma;

    if (begin < vma->begin) {
        return -ENOMEM;
    }

    bool is_continuous = true;

    while (1) {
        if (!!(vma->flags & VMA_INTERNAL) != is_internal) {
            return -EACCES;
        }
        if (prot & PROT_GROWSDOWN) {
            if (!(vma->flags & MAP_GROWSDOWN)) {
                return -EINVAL;
            }
        }
        if (vma->file && (vma->flags & MAP_SHARED)) {
            if (!is_file_prot_matching(vma->file, prot)) {
                return -EACCES;
            }
        }

        if (end <= vma->end) {
            break;
        }

        prev = vma;

        vma = _get_next_vma(vma);
        if (!vma) {
            is_continuous = false;
            break;
        }

        is_continuous &= prev->end == vma->begin;
    }

    if (!is_continuous) {
        /* XXX: When Linux fails with such an error, it sill changes permissions of the first
         * continuous fragment. Maybe we should emulate this weird behavior? */
        return -ENOMEM;
    }

    vma = first_vma;

    /* For PROT_GROWSDOWN we just pretend that `vma->begin == begin`. */
    if (vma->begin < begin && !(prot & PROT_GROWSDOWN)) {
        struct shim_vma* new_vma1 = *new_vma_ptr1;
        *new_vma_ptr1 = NULL;

        split_vma(vma, new_vma1, begin);
        vma_update_prot(new_vma1, prot);

        struct shim_vma* next = _get_next_vma(vma);

        avl_tree_insert(&vma_tree, &new_vma1->tree_node);

        if (end < new_vma1->end) {
            struct shim_vma* new_vma2 = *new_vma_ptr2;
            *new_vma_ptr2 = NULL;

            split_vma(new_vma1, new_vma2, end);
            vma_update_prot(new_vma2, vma->prot);

            avl_tree_insert(&vma_tree, &new_vma2->tree_node);
            return 0;
        }

        /* Error checking at the begining ensures we always have the next node. */
        assert(next);
        vma = next;
    }

    while (vma->end <= end) {
        vma_update_prot(vma, prot);

#ifdef DEBUG
        struct shim_vma* prev = vma;
#endif
        vma = _get_next_vma(vma);
        if (!vma) {
            /* We've reached the very last vma. */
            assert(prev->end == end);
            return 0;
        }
    }

    if (end <= vma->begin) {
        return 0;
    }

    struct shim_vma* new_vma2 = *new_vma_ptr2;
    *new_vma_ptr2 = NULL;

    split_vma(vma, new_vma2, end);
    vma_update_prot(vma, prot);

    avl_tree_insert(&vma_tree, &new_vma2->tree_node);

    return 0;
}

int bkeep_mprotect(void* addr, size_t length, int prot, bool is_internal) {
    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct shim_vma* vma1 = alloc_vma();
    if (!vma1) {
        return -ENOMEM;
    }
    struct shim_vma* vma2 = alloc_vma();
    if (!vma2) {
        free_vma(vma1);
        return -ENOMEM;
    }

    spinlock_lock(&vma_tree_lock);
    int ret = _vma_bkeep_change((uintptr_t)addr, (uintptr_t)addr + length, prot, is_internal, &vma1,
                                &vma2);
    spinlock_unlock(&vma_tree_lock);

    if (vma1) {
        free_vma(vma1);
    }
    if (vma2) {
        free_vma(vma2);
    }

    return ret;
}

/* TODO consider:
 * maybe it's worth to keep another tree, complementary to `vma_tree`, that would hold free areas.
 * It would give O(logn) unmapped lookup, which now is O(n) in the worst case, but it would also
 * double the memory usage of this subsystem and add some complexity.
 * Another idea is to merge adjacent vmas, that are not backed by any file and have the same prot
 * and flags (the question is whether that happens often). */
/* This function allocates at most 1 vma. If in the future it uses more, `_vma_malloc` should be
 * updated as well. */
int bkeep_mmap_any_in_range(void* _bottom_addr, void* _top_addr, size_t length, int prot, int flags,
                            struct shim_handle* file, uint64_t offset, const char* comment,
                            void** ret_val_ptr) {
    assert(_bottom_addr < _top_addr);

    if (!length || !IS_ALLOC_ALIGNED(length)) {
        return -EINVAL;
    }
    if (!IS_ALLOC_ALIGNED_PTR(_bottom_addr) || !IS_ALLOC_ALIGNED_PTR(_top_addr)) {
        return -EINVAL;
    }

    uintptr_t top_addr    = (uintptr_t)_top_addr;
    uintptr_t bottom_addr = (uintptr_t)_bottom_addr;
    int ret = 0;
    uintptr_t ret_val = 0;

#ifdef MAP_32BIT /* x86_64-specific */
    if (flags & MAP_32BIT) {
        /* Only consider first 2 gigabytes. */
        top_addr = MIN(top_addr, 1ul << 31);
        if (bottom_addr >= top_addr) {
            return -ENOMEM;
        }
    }
#endif

    struct shim_vma* new_vma = alloc_vma();
    if (!new_vma) {
        return -ENOMEM;
    }
    new_vma->prot  = prot;
    new_vma->flags = filter_saved_flags(flags) | ((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    new_vma->file  = file;
    if (new_vma->file) {
        get_handle(new_vma->file);
    }
    new_vma->offset = file ? offset : 0;
    copy_comment(new_vma, comment ?: "");

    spinlock_lock(&vma_tree_lock);

    struct shim_vma* vma = _lookup_vma(top_addr);
    uintptr_t max_addr;
    if (!vma) {
        vma = _get_last_vma();
        max_addr = top_addr;
    } else {
        max_addr = MIN(top_addr, vma->begin);
        vma = _get_prev_vma(vma);
    }
    assert(!vma || vma->end <= max_addr);

    while (vma && bottom_addr <= vma->end) {
        assert(vma->end <= max_addr);
        if (max_addr - vma->end >= length) {
            goto out_found;
        }

        max_addr = vma->begin;
        vma = _get_prev_vma(vma);
    }

    if (!(bottom_addr <= max_addr && max_addr - bottom_addr >= length)) {
        ret = -ENOMEM;
        goto out;
    }

out_found:
    new_vma->end   = max_addr;
    new_vma->begin = new_vma->end - length;

    avl_tree_insert(&vma_tree, &new_vma->tree_node);

    ret_val = new_vma->begin;
    new_vma = NULL;

out:
    spinlock_unlock(&vma_tree_lock);
    if (new_vma) {
        free_vma(new_vma);
    }
    if (ret >= 0) {
        *ret_val_ptr = (void*)ret_val;
    }
    return ret;
}

int bkeep_mmap_any(size_t length, int prot, int flags, struct shim_handle* file, uint64_t offset,
                   const char* comment, void** ret_val_ptr) {
    return bkeep_mmap_any_in_range(g_pal_control->user_address.start,
                                   g_pal_control->user_address.end,
                                   length, prot, flags, file, offset, comment, ret_val_ptr);
}

int bkeep_mmap_any_aslr(size_t length, int prot, int flags, struct shim_handle* file,
                        uint64_t offset, const char* comment, void** ret_val_ptr) {
    int ret;
    ret = bkeep_mmap_any_in_range(g_pal_control->user_address.start, g_aslr_addr_top, length, prot,
                                  flags, file, offset, comment, ret_val_ptr);
    if (ret >= 0) {
        return ret;
    }

    return bkeep_mmap_any(length, prot, flags, file, offset, comment, ret_val_ptr);
}

static void dump_vma(struct shim_vma_info* vma_info, struct shim_vma* vma) {
    vma_info->addr        = (void*)vma->begin;
    vma_info->length      = vma->end - vma->begin;
    vma_info->prot        = vma->prot;
    vma_info->flags       = vma->flags;
    vma_info->file_offset = vma->offset;
    vma_info->file        = vma->file;
    if (vma_info->file) {
        get_handle(vma_info->file);
    }
    static_assert(sizeof(vma_info->comment) == sizeof(vma->comment), "Comments sizes do not match");
    memcpy(vma_info->comment, vma->comment, sizeof(vma_info->comment));
}

int lookup_vma(void* addr, struct shim_vma_info* vma_info) {
    assert(vma_info);
    int ret = 0;

    spinlock_lock(&vma_tree_lock);
    struct shim_vma* vma = _lookup_vma((uintptr_t)addr);
    if (!vma || !is_addr_in_vma((uintptr_t)addr, vma)) {
        ret = -ENOENT;
        goto out;
    }

    dump_vma(vma_info, vma);

out:
    spinlock_unlock(&vma_tree_lock);
    return ret;
}

struct adj_visitor_ctx {
    int prot;
    bool is_ok;
};

static bool adj_visitor(struct shim_vma* vma, void* visitor_arg) {
    struct adj_visitor_ctx* ctx = visitor_arg;
    bool is_ok = !(vma->flags & (VMA_INTERNAL | VMA_UNMAPPED));
    is_ok &= (vma->prot & ctx->prot) == ctx->prot;
    ctx->is_ok &= is_ok;
    return is_ok;
}

bool is_in_adjacent_user_vmas(const void* addr, size_t length, int prot) {
    uintptr_t begin = (uintptr_t)addr;
    uintptr_t end = begin + length;
    assert(begin <= end);

    struct adj_visitor_ctx ctx = {
        .prot = prot,
        .is_ok = true,
    };

    spinlock_lock(&vma_tree_lock);
    bool is_continuous = _traverse_vmas_in_range(begin, end, adj_visitor, &ctx);
    spinlock_unlock(&vma_tree_lock);

    return is_continuous && ctx.is_ok;
}

static size_t dump_all_vmas_with_buf(struct shim_vma_info* infos, size_t max_count,
                                     bool include_unmapped) {
    size_t size = 0;
    struct shim_vma_info* vma_info = infos;

    spinlock_lock(&vma_tree_lock);
    struct shim_vma* vma;

    for (vma = _get_first_vma(); vma; vma = _get_next_vma(vma)) {
        if (vma->flags & ((include_unmapped ? 0 : VMA_UNMAPPED) | VMA_INTERNAL)) {
            continue;
        }
        if (size < max_count) {
            dump_vma(vma_info, vma);
            vma_info++;
        }
        size++;
    }

    spinlock_unlock(&vma_tree_lock);

    return size;
}

int dump_all_vmas(struct shim_vma_info** ret_infos, size_t* ret_count, bool include_unmapped) {
    size_t count = DEFAULT_VMA_COUNT;

    while (true) {
        struct shim_vma_info* vmas = calloc(count, sizeof(*vmas));
        if (!vmas) {
            return -ENOMEM;
        }

        size_t needed_count = dump_all_vmas_with_buf(vmas, count, include_unmapped);
        if (needed_count <= count) {
            *ret_infos = vmas;
            *ret_count = needed_count;
            return 0;
        }

        free_vma_info_array(vmas, count);
        count = needed_count;
    }
}

void free_vma_info_array(struct shim_vma_info* vma_infos, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (vma_infos[i].file) {
            put_handle(vma_infos[i].file);
        }
    }

    free(vma_infos);
}

struct madvise_dontneed_ctx {
    uintptr_t begin;
    uintptr_t end;
    int error;
};

static bool madvise_dontneed_visitor(struct shim_vma* vma, void* visitor_arg) {
    struct madvise_dontneed_ctx* ctx = (struct madvise_dontneed_ctx*)visitor_arg;

    if (vma->flags & (VMA_UNMAPPED | VMA_INTERNAL)) {
        ctx->error = -EINVAL;
        return false;
    }

    if (vma->file) {
        if (vma->flags & VMA_TAINTED) {
            /* Resetting writable file-backed mappings is not yet implemented. */
            ctx->error = -ENOSYS;
            return false;
        }
        /* MADV_DONTNEED resets file-based mappings to the original state, which is a no-op for
         * non-tainted mappings. */
        return true;
    }

    if (!(vma->prot & PROT_WRITE)) {
        ctx->error = -ENOSYS; // Zeroing non-writable mappings is not yet implemented.
        return false;
    }

    uintptr_t zero_start = MAX(ctx->begin, vma->begin);
    uintptr_t zero_end = MIN(ctx->end, vma->end);
    memset((void*)zero_start, 0, zero_end - zero_start);
    return true;
}

int madvise_dontneed_range(uintptr_t begin, uintptr_t end) {
    struct madvise_dontneed_ctx ctx = {
        .begin = begin,
        .end = end,
        .error = 0,
    };

    spinlock_lock(&vma_tree_lock);
    bool is_continuous = _traverse_vmas_in_range(begin, end, madvise_dontneed_visitor, &ctx);
    spinlock_unlock(&vma_tree_lock);

    if (!is_continuous)
        return -ENOMEM;
    return ctx.error;
}


BEGIN_CP_FUNC(vma) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_vma_info));

    struct shim_vma_info* vma = (struct shim_vma_info*)obj;
    struct shim_vma_info* new_vma = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(*vma));
        ADD_TO_CP_MAP(obj, off);

        new_vma = (struct shim_vma_info*)(base + off);
        *new_vma = *vma;

        if (vma->file)
            DO_CP(handle, vma->file, &new_vma->file);

        void* need_mapped = vma->addr;

        /* Check whether we need to checkpoint memory this vma bookkeeps. */
        if ((vma->flags & VMA_TAINTED || !vma->file) && !(vma->flags & VMA_UNMAPPED)) {
            void* send_addr  = vma->addr;
            size_t send_size = vma->length;
            if (vma->file) {
                /*
                 * Chia-Che 8/13/2017:
                 * A fix for cloning a private VMA which maps a file to a process.
                 *
                 * (1) Application can access any page backed by the file, wholly
                 *     or partially.
                 *
                 * (2) Access beyond the last file-backed page will cause SIGBUS.
                 *     For reducing fork latency, the following code truncates the
                 *     memory size for migrating a process. The memory size is
                 *     truncated to the file size, round up to pages.
                 *
                 * (3) Data in the last file-backed page is valid before or after
                 *     forking. Has to be included in process migration.
                 */
                uint64_t file_len = 0;
                if (!get_file_size(vma->file, &file_len)
                        && vma->file_offset + vma->length > file_len) {
                    send_size = file_len > vma->file_offset ? file_len - vma->file_offset : 0;
                    send_size = ALLOC_ALIGN_UP(send_size);
                }
            }
            if (send_size > 0) {
                struct shim_mem_entry* mem;
                DO_CP_SIZE(memory, send_addr, send_size, &mem);
                mem->prot = LINUX_PROT_TO_PAL(vma->prot, /*map_flags=*/0);

                need_mapped = vma->addr + vma->length;
            }
        }
        ADD_CP_FUNC_ENTRY(off);
        ADD_CP_ENTRY(ADDR, need_mapped);
    } else {
        new_vma = (struct shim_vma_info*)(base + off);
    }

    if (objp)
        *objp = (void*)new_vma;
}
END_CP_FUNC(vma)

BEGIN_RS_FUNC(vma) {
    struct shim_vma_info* vma = (void*)(base + GET_CP_FUNC_ENTRY());
    void* need_mapped = (void*)GET_CP_ENTRY(ADDR);
    CP_REBASE(vma->file);

    DEBUG_RS("vma: %p-%p flags 0x%x prot 0x%08x comment \"%s\"", vma->addr,
             vma->addr + vma->length, vma->flags, vma->prot, vma->comment);

    int ret = bkeep_mmap_fixed(vma->addr, vma->length, vma->prot, vma->flags | MAP_FIXED, vma->file,
                               vma->file_offset, vma->comment);
    if (ret < 0)
        return ret;

    if (!(vma->flags & VMA_UNMAPPED)) {
        if (vma->file) {
            struct shim_fs* fs = vma->file->fs;
            get_handle(vma->file);

            if (need_mapped < vma->addr + vma->length) {
                /* first try, use hstat to force it resumes pal handle */
                if (!fs || !fs->fs_ops || !fs->fs_ops->mmap) {
                    return -EINVAL;
                }

                void* addr = need_mapped;
                int ret = fs->fs_ops->mmap(vma->file, &addr, vma->addr + vma->length - need_mapped,
                                           vma->prot, vma->flags | MAP_FIXED,
                                           vma->file_offset + (need_mapped - vma->addr));

                if (ret < 0)
                    return ret;
                if (!addr)
                    return -ENOMEM;
                if (addr != need_mapped)
                    return -EACCES;

                need_mapped += vma->length;
            }
        }

        if (need_mapped < vma->addr + vma->length) {
            int ret = DkVirtualMemoryAlloc(need_mapped, vma->addr + vma->length - need_mapped,
                                           /*alloc_type=*/0,
                                           LINUX_PROT_TO_PAL(vma->prot, /*map_flags=*/0));
            if (ret >= 0) {
                need_mapped += vma->length;
            }
        }

        if (need_mapped < vma->addr + vma->length) {
            log_error("vma %p-%p cannot be allocated!", need_mapped, vma->addr + vma->length);
            return -ENOMEM;
        }
    }
}
END_RS_FUNC(vma)

BEGIN_CP_FUNC(all_vmas) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    size_t count;
    struct shim_vma_info* vmas;
    int ret = dump_all_vmas(&vmas, &count, /*include_unmapped=*/true);
    if (ret < 0) {
        return ret;
    }

    for (struct shim_vma_info* vma = &vmas[count - 1];; vma--) {
        DO_CP(vma, vma, NULL);
        if (vma == vmas)
            break;
    }

    free_vma_info_array(vmas, count);
}
END_CP_FUNC_NO_RS(all_vmas)


static void debug_print_vma(struct shim_vma* vma) {
    log_debug("[0x%lx-0x%lx] prot=0x%x flags=0x%x%s%s file=%p (offset=%ld)%s%s",
              vma->begin, vma->end,
              vma->prot,
              vma->flags & ~(VMA_INTERNAL | VMA_UNMAPPED),
              vma->flags & VMA_INTERNAL ? "(INTERNAL " : "(",
              vma->flags & VMA_UNMAPPED ? "UNMAPPED)" : ")",
              vma->file,
              vma->offset,
              vma->comment[0] ? " comment=" : "",
              vma->comment[0] ? vma->comment : "");
}

void debug_print_all_vmas(void) {
    spinlock_lock(&vma_tree_lock);

    struct shim_vma* vma = _get_first_vma();
    while (vma) {
        debug_print_vma(vma);
        vma = _get_next_vma(vma);
    }

    spinlock_unlock(&vma_tree_lock);
}
