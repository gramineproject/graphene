#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_LENGTH  0x10000f000
#define TEST_LENGTH2 0x8000f000

int main() {
    FILE* fp = fopen("testfile", "a+");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    int rv = ftruncate(fileno(fp), TEST_LENGTH);
    if (rv) {
        perror("ftruncate");
        return 1;
    } else {
        printf("large-mmap: ftruncate OK\n");
    }

    void* a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
    if (a == MAP_FAILED) {
        perror("mmap 1");
        return 1;
    }
    ((char*)a)[0x80000000] = 0xff;
    printf("large-mmap: mmap 1 completed OK\n");

    rv = munmap(a, TEST_LENGTH2);
    if (rv) {
        perror("mumap");
        return 1;
    }

    a = mmap(NULL, TEST_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
    if (a == MAP_FAILED) {
        perror("mmap 2");
        return 1;
    }
    ((char*)a)[0x100000000] = 0xff;
    printf("large-mmap: mmap 2 completed OK\n");

    return 0;
}
