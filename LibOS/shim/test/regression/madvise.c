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

    void* m = mmap(NULL, PAGES_CNT * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!m)
        err(1, "mmap()");

    for (int i = 0; i < PAGES_CNT; i++) {
        *(int*)(m + page_size * i) = 0x123;
        *(int*)(m + page_size * i + page_size - sizeof(int)) = 0x321;
    }

    /* Clear pages one by one */
    bool cleared[PAGES_CNT] = {false};
    for (int i = 0; i < PAGES_CNT; i++) {
        int perm_idx = ((i + 123) * 307) % PAGES_CNT; /* make the traverse non-sequential */
        void* curr = m + page_size * perm_idx;

        int res = madvise(curr, page_size, MADV_DONTNEED);
        if (res)
            err(1, "madvise(%p, 0x%zx, MADV_DONTNEED) failed", curr, page_size);
        cleared[perm_idx] = true;

        /* Rescan the whole range and verify all magic values */
        for (int j = 0; j < PAGES_CNT; j++) {
            int expected1 = 0x123;
            int expected2 = 0x321;
            if (cleared[j]) {
                expected1 = expected2 = 0;
            }
            int actual1 = *(int*)(m + page_size * j);
            int actual2 = *(int*)(m + page_size * j + page_size - sizeof(int));
            if (actual1 != expected1 || actual2 != expected2) {
                errx(1, "page %d has wrong contents: 0x%x != 0x%x or 0x%x != 0x%x", j, actual1,
                     expected1, actual2, expected2);
            }
        }
    }
    puts("TEST OK");
    return 0;
}
