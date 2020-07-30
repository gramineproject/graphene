#include "api.h"
#include "linux_utils.h"
#include "sysdep-arch.h"

#define BUF_SIZE 1023u

char* get_main_exec_path(void) {
    char* buf = malloc(BUF_SIZE + 1);
    if (!buf) {
        return NULL;
    }

    ssize_t len = INLINE_SYSCALL(readlink, 3, "/proc/self/exe", buf, BUF_SIZE);
    if (len < 0) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';

    return buf;
}
