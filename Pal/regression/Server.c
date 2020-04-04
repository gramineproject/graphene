/* The server test program that accepts multiple TCP connections at the same
 * time. A port number is taken as argument. If a port is locked up, try
 * another one.
 *
 * Run this progam with a simple tcp client, like netcat.  For instance:
 *
 * Start the server:
 *  ../src/libpal.so file:./Server.manifest 4000
 *
 * Run the client:
 *   nc localhost 4000
 *   [ type strings here, see them appear on the console ]
 */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

#define MAX_HANDLES 8

int main(int argc, char** argv) {
    if (argc < 2) {
        pal_printf("Specify the port to open!\n");
        return 0;
    }

    char uri[60];
    snprintf(uri, sizeof(uri), "tcp.srv:127.0.0.1:%s", argv[1]);

    PAL_HANDLE srv = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0, PAL_CREATE_TRY, 0);
    if (srv == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    void* buffer = (void*)DkVirtualMemoryAlloc(NULL, 4096, 0, PAL_PROT_READ | PAL_PROT_WRITE);
    if (!buffer) {
        pal_printf("DkVirtualMemoryAlloc failed\n");
        return -1;
    }

    PAL_HANDLE hdls[MAX_HANDLES];
    PAL_FLG events[MAX_HANDLES];
    PAL_FLG revents[MAX_HANDLES];

    int nhdls = 1;
    hdls[0]   = srv;

    while (1) {
        for (int i = 0; i < MAX_HANDLES; i++) {
            events[i]  = PAL_WAIT_READ | PAL_WAIT_WRITE;
            revents[i] = 0;
        }

        PAL_BOL polled = DkStreamsWaitEvents(nhdls, hdls, events, revents, NO_TIMEOUT);
        if (!polled)
            continue;

        for (int i = 0; i < MAX_HANDLES; i++) {
            if (revents[i]) {
                if (hdls[i] == srv) {
                    /* event on server -- must be client connecting */
                    PAL_HANDLE client_hdl = DkStreamWaitForClient(srv);
                    if (!client_hdl)
                        continue;

                    if (nhdls >= MAX_HANDLES) {
                        pal_printf("[ ] connection rejected\n");
                        DkObjectClose(client_hdl);
                        continue;
                    }

                    pal_printf("[%d] receive new connection\n", nhdls);
                    hdls[nhdls++] = client_hdl;
                } else if (revents[i] & PAL_WAIT_READ) {
                    /* event on client -- must read from client */
                    int bytes = DkStreamRead(hdls[i], 0, 4096, buffer, NULL, 0);
                    if (bytes == 0) {
                        DkObjectClose(hdls[i]);
                        for (int j = i + 1; j < nhdls; j++)
                            hdls[j - 1] = hdls[j];
                        nhdls--;
                        continue;
                    }
                    int last_byte = bytes < 4096 ? bytes : 4095;
                    ((char*)buffer)[last_byte] = 0;
                    pal_printf("[%d] %s", i, (char*)buffer);

                }
            }
        }
    }

    return 0;
}
