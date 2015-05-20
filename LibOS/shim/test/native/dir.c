/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TESTDIR "testdir"

int main(int argc, char ** argv)
{
    int ret = 0;

    if ((ret = rmdir(TESTDIR)) < 0 && errno != ENOENT) {
        perror("rmdir");
        exit(1);
    }

    if ((ret = mkdir(TESTDIR, 0700)) < 0) {
        perror("mkdir");
        exit(1);
    }

    if ((ret = creat(TESTDIR "/file", 0600)) < 0) {
        perror("open");
        exit(1);
    }

    if ((ret = unlink(TESTDIR "/file")) < 0) {
        perror("unlink");
        exit(1);
    }

    if ((ret = rmdir(TESTDIR)) < 0) {
        perror("mkdir");
        exit(1);
    }

    return 0;
}
