/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */
#define _GNU_SOURCE
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/* Unfortunately LTP tests for madvise require a lot of other complex features (e.g. mount or
 * cgroup), so let's test it by ourselves. */

#define PAGES_CNT 128

int main() {
    size_t page_size = getpagesize();

    char* m = (char*)mmap(NULL, PAGES_CNT * page_size,
                          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    if (m == MAP_FAILED)
        err(1, "mmap()");

    for (size_t i = 0; i < PAGES_CNT; i++) {
        *(int*)(m + page_size * i) = 0x123;
        *(int*)(m + page_size * i + page_size - sizeof(int)) = 0x321;
    }

    /* Clear pages one by one */
    bool cleared_first[PAGES_CNT] = {false};
    bool cleared_second[PAGES_CNT] = {false};
    for (size_t i = 0; i < PAGES_CNT; i++) {
        size_t perm_idx = ((i + 123) * 51) % PAGES_CNT; /* make the traverse non-sequential */
        char* addr = m + page_size * perm_idx;
        size_t size = page_size;

        if (i * 307 & 0x80) { /* some bad-quality pseudo-random (but deterministic) condition */
            cleared_first[perm_idx] = true;
        } else {
            addr += sizeof(int);
            size -= sizeof(int);
        }
        if (i * 307 & 0x100) {
            cleared_second[perm_idx] = true;
        } else {
            size -= sizeof(int);
        }


        int res = madvise(addr, size, MADV_DONTNEED);
        if (res)
            err(1, "madvise(%p, 0x%zx, MADV_DONTNEED) failed", addr, size);

        /* Rescan the whole range and verify all magic values */
        for (size_t j = 0; j < PAGES_CNT; j++) {
            int expected1 = cleared_first[j] ? 0 : 0x123;
            int expected2 = cleared_second[j] ? 0 : 0x321;
            int actual1 = *(int*)(m + page_size * j);
            int actual2 = *(int*)(m + page_size * j + page_size - sizeof(int));
            if (actual1 != expected1 || actual2 != expected2) {
                errx(1, "page %zu has wrong contents: 0x%x != 0x%x or 0x%x != 0x%x", j, actual1,
                     expected1, actual2, expected2);
            }
        }
    }
    puts("TEST OK");
    return 0;
}
