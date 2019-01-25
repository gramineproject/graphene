/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>

int main (int argc, const char ** argv)
{
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
