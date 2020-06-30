#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    char* ptr = mmap(NULL, 0x3000, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        err(1, "mmap");
    }

    int x = mprotect(ptr + 0x1000, 0x1000, PROT_READ | PROT_WRITE | PROT_GROWSDOWN);
    if (x >= 0) {
        printf("mprotect succedded unexpectedly!\n");
        return 1;
    }
    if (errno != EINVAL) {
        printf("Wrong errno value: %d\n", errno);
        return 1;
    }

    if (munmap(ptr, 0x3000) < 0) {
        err(1, "munmap");
    }

    ptr = mmap(NULL, 0x3000, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
    if (ptr == MAP_FAILED) {
        err(1, "mmap");
    }

    if (mprotect(ptr + 0x1000, 0x1000, PROT_READ | PROT_WRITE | PROT_GROWSDOWN) < 0) {
        err(1, "mprotect");
    }

    __asm__ volatile("movb $0x61, (%0)"
            :
            : "r"(ptr)
            : "memory");

    if (ptr[0] != 'a') {
        printf("Value was not written to mem!\n");
        return 1;
    }

    puts("TEST OK");
    return 0;
}
