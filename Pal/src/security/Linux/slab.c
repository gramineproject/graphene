/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <linux/unistd.h>
#include <asm/mman.h>
#include <linux_list.h>

#include "utils.h"

int heap_alloc_size = 4096 * 4;

struct heap {
    struct list_head list;
    int used;
    int size;
};

LIST_HEAD(heap_list);

void * malloc (int size)
{
    void * ptr = NULL;
    struct heap * h;

    list_for_each_entry(h, &heap_list, list)
        if (h->used + size <= h->size) {
            ptr = (void *) h + h->used;
            h->used += size;
            return ptr;
        }

    while (heap_alloc_size < size)
        heap_alloc_size *= 2;

    h = (void *) INLINE_SYSCALL(mmap, 6, NULL, heap_alloc_size,
                                PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (IS_ERR_P(h))
        return NULL;

    ptr = (void *) h + sizeof(struct heap);

    h->used = sizeof(struct heap) + size;
    h->size = heap_alloc_size;
    INIT_LIST_HEAD(&h->list);
    list_add_tail(&h->list, &heap_list);
    heap_alloc_size *= 2;

    return ptr;
}

void free (void * mem)
{
    /* no freeing, the memory will be freed in the end */
}

int free_heaps (void)
{
    struct heap * h, * n;

    list_for_each_entry_safe(h, n, &heap_list, list) {
        list_del(&h->list);
        INLINE_SYSCALL(munmap, 2, h, h->size);
    }

    return 0;
}
