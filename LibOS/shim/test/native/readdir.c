/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>

int main(int argc, char ** argv)
{
    struct dirent * dirent;

    DIR * dir = opendir(".");

    while ((dirent = readdir(dir)))
        printf("found %s\n", dirent->d_name);

    closedir(dir);

    return 0;
}
