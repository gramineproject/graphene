/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

#define file_uri "file:test.txt"

char str[12];

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE out = DkStreamOpen(file_uri, PAL_ACCESS_RDWR,
                                  PAL_SHARE_OWNER_W | PAL_SHARE_OWNER_R,
                                  PAL_CREAT_TRY, 0);

    if (out == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    str[0] = 'H';
    str[1] = 'e';
    str[2] = 'l';
    str[3] = 'l';
    str[4] = 'o';
    str[5] = ' ';
    str[6] = 'W';
    str[7] = 'o';
    str[8] = 'r';
    str[9] = 'l';
    str[10] = 'd';
    str[11] = 0;

    int bytes = DkStreamWrite(out, 0, 11, str, NULL);

    if (!bytes) {
        pal_printf("DkStreamWrite failed\n");
        return -1;
    }

    DkObjectClose(out);

    PAL_HANDLE in = DkStreamOpen(file_uri, PAL_ACCESS_RDONLY, 0, 0, 0);

    bytes = DkStreamRead(in, 0, 20, str, NULL, 0);

    if (!bytes) {
        pal_printf("DkStreamRead failed\n");
        return -1;
    }

    pal_printf("%s\n", str);

    DkStreamDelete(in, 0);

    PAL_HANDLE del = DkStreamOpen(file_uri, PAL_ACCESS_RDWR, 0, 0, 0);

    if (del) {
        pal_printf("DkStreamDelete failed\n");
        return -1;
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
