/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

#define NTRIES  10

int main (int argc, char ** argv)
{
    unsigned long pipeid;
    char uri[40];

    DkRandomBitsRead(&pipeid, sizeof(unsigned long));
    pipeid = pipeid % 1024;

    snprintf(uri, 40, "pipe.srv:%d", pipeid);

    PAL_HANDLE srv = DkStreamOpen(uri, 0, 0,
                                  PAL_CREAT_TRY|PAL_CREAT_ALWAYS, 0);

    if (!srv) {
        pal_printf("not able to create server (%s)\n", uri);
        return -1;
    }

    snprintf(uri, 40, "pipe:%d", pipeid);

    PAL_HANDLE cli = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0,
                                  PAL_CREAT_TRY|PAL_CREAT_ALWAYS, 0);

    if (!cli) {
        pal_printf("not able to create client\n");
        return -1;
    }

    DkStreamGetName(cli, uri, 40);

    pal_printf("pipe connect as %s\n", uri);

    PAL_HANDLE conn = DkStreamWaitForClient(srv);

    if (!cli) {
         pal_printf("not able to accept client\n");
         return -1;
    }

    DkStreamGetName(conn, uri, 40);

    pal_printf("pipe accepted as %s\n", uri);

    DkObjectClose(srv);

    int i;

    for (i = 0 ; i < NTRIES ; i++) {
        int bytes = DkStreamWrite(cli, 0, 12, "Hello World", NULL);

        if (!bytes) {
            pal_printf("not able to send to client\n");
            return -1;
        }
    }

    for (i = 0 ; i < NTRIES ; i++) {
        char buffer[12];
        int bytes = DkStreamRead(conn, 0, 12, buffer, NULL, 0);

        if (!bytes) {
            pal_printf("not able to receive from server\n");
            return -1;
        }

        pal_printf("read from server: %s\n", buffer);
    }

    DkObjectClose(cli);
    DkObjectClose(conn);

    return 0;
}

