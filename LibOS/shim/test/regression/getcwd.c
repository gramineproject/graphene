#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>

/* NOTE: cwd_buf resides in BSS section which starts right after DATA section;
 * under Linux-SGX, BSS section is in a separate VMA from DATA section but
 * cwd_buf spans both sections. This test checks among others the correctness
 * of test_user_memory() spanning several adjacent VMAs. */
static char cwd_buf[PATH_MAX];

int main(int argc, char ** argv) {
    char *cwd = NULL;
    cwd = getcwd(cwd_buf, sizeof(cwd_buf));

    if (!cwd) {
        perror("getcwd failed\n");
    } else {
        printf("getcwd succeeded: %s\n", cwd);
    }

    return 0;
}
