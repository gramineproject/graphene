/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* The server test program that accept multiple TCP connection at the same
 * time. A port number is taken as argument. If a port is locked up, try
 * another one. 
 * 
 * Run this progam with a simple tcp client, like netcat.  For instance:
 *
 * Start the server:
 *  ../src/libpal.so file:./Server.manifest 4000
 *
 *
 * Run the client:
 *   nc localhost 4000
 *   [ type strings here, see them appear on the console ]
 */


#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main (int argc, char ** argv)
{
    if (argc < 2) {
        pal_printf("specify the port to open\n");
        return 0;
    }

    char uri[60];
    snprintf(uri, 60, "tcp.srv:127.0.0.1:%s", argv[1]);

    PAL_HANDLE srv = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0,
                                  PAL_CREAT_TRY, 0);

    if (srv == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    void * buffer = (void *) DkVirtualMemoryAlloc(NULL, 4096, 0,
                                                  PAL_PROT_READ|PAL_PROT_WRITE);
    if (!buffer) {
        pal_printf("DkVirtualMemoryAlloc failed\n");
        return -1;
    }

    PAL_HANDLE hdls[8];
    int nhdls = 1, i;
    hdls[0] = srv;

    while(1) {
        PAL_HANDLE hdl = DkObjectsWaitAny(nhdls, hdls, NO_TIMEOUT);

        if (!hdl)
            continue;

        if (hdl == srv) {
            hdl = DkStreamWaitForClient(srv);

            if (!hdl)
                continue;

            if (nhdls >= 8) {
                pal_printf("[ ] connection rejected\n");
                DkObjectClose(hdl);
                continue;
            }

            pal_printf("[%d] receive new connection\n", nhdls);
            hdls[nhdls++] = hdl;
            continue;
        }

        int cnt = 0;
        for (i = 0 ; i < nhdls ; i++)
            if (hdls[i] == hdl)
                cnt = i;

        int bytes = DkStreamRead(hdl, 0, 4096, buffer, NULL, 0);

        if (bytes == 0) {
            DkObjectClose(hdls[cnt]);
            if (cnt != nhdls - 1)
                hdls[cnt] = hdls[nhdls - 1];
            nhdls--;
            continue;
        }

        ((char *) buffer)[bytes] = 0;

        pal_printf("[%d] %s", cnt, (char *) buffer);
    }
    return 0;
}
