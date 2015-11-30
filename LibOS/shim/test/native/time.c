/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <sys/time.h>

int main(int argc, char ** argv)
{
    struct timeval time;

    int ret = gettimeofday(&time, NULL);

    if (ret < 0) {
        perror("gettimeofday");
        return -1;
    }

    printf("Current timestamp: %ld\n", time.tv_sec);
    return 0;
}
