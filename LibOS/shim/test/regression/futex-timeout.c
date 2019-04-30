#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>

int main (int argc, const char** argv) {
    int myfutex = 0;
    struct timespec t = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    printf("hello\n");
    syscall(SYS_futex, &myfutex, FUTEX_WAIT, 0, &t, NULL, 0);
    printf("world\n");

    return 0;
}
