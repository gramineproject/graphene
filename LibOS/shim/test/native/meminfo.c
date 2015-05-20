/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main (int argc, char ** argv)
{
    FILE * cpuinfo = fopen("/proc/meminfo", "rb");
    char * arg = 0;
    size_t size = 0;

    if (!cpuinfo)
        return errno;

    while(getdelim(&arg, &size, 0, cpuinfo) != -1)
        puts(arg);

    free(arg);
    fclose(cpuinfo);
    return 0;
}
