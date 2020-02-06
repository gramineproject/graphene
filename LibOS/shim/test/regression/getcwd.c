#define _GNU_SOURCE
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static char bss_cwd_buf[PATH_MAX];

int main(int argc, char** argv) {
    char* cwd = NULL;

    /* Option 1: use global variable.
     * bss_cwd_buf resides in BSS section which starts right after DATA section;
     * under Linux-SGX, BSS section is in a separate VMA from DATA section but
     * cwd_buf spans both sections. This checks the correctness of internal
     * test_user_memory() spanning several adjacent VMAs. */
    cwd = getcwd(bss_cwd_buf, sizeof(bss_cwd_buf));
    if (!cwd) {
        perror("[bss_cwd_buf] getcwd failed\n");
    } else {
        printf("[bss_cwd_buf] getcwd succeeded: %s\n", cwd);
    }

    /* Option 2: use 2-page mmapped variable.
     * mmapped_cwd_buf resides on the heap and occupies two consecutive pages;
     * we divide the original single VMA into two adjacent VMAs via mprotect().
     * This checks the correctness of internal test_user_memory() spanning
     * several adjacent VMAs. */
    void* mmapped_cwd_buf = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC,
                                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mmapped_cwd_buf == MAP_FAILED) {
        perror("mmap failed\n");
        return 1;
    }
    int ret = mprotect(mmapped_cwd_buf, 4096, PROT_READ | PROT_WRITE);
    if (ret < 0) {
        perror("mprotect failed\n");
        return 1;
    }
    cwd = getcwd(mmapped_cwd_buf, 4096 * 2);
    if (!cwd) {
        perror("[mmapped_cwd_buf] getcwd failed\n");
    } else {
        printf("[mmapped_cwd_buf] getcwd succeeded: %s\n", cwd);
    }

    munmap(mmapped_cwd_buf, 4096 * 2);
    return 0;
}
