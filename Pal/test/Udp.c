#include "api.h"
#include "pal.h"
#include "pal_debug.h"

#define NTRIES 10

int main(int argc, char** argv) {
    char addr[40];
    int i;

    if (argc == 1) {
        unsigned long start = DkSystemTimeQuery();

        const char* newargs[3] = {"Udp", "child", NULL};

        PAL_HANDLE srv = DkStreamOpen("udp.srv:127.0.0.1:8000", 0, 0, 0, 0);

        if (!srv) {
            pal_printf("not able to create server\n");
            return -1;
        }

        DkStreamGetName(srv, addr, 40);
        pal_printf("server bound on %s\n", addr);

        PAL_HANDLE proc = DkProcessCreate("file:Udp", newargs);

        for (i = 0; i < NTRIES; i++) {
            char buffer[20];
            int bytes = DkStreamRead(srv, 0, 20, buffer, addr, 40);

            if (!bytes) {
                pal_printf("not able to receive from client\n");
                return -1;
            }

            pal_printf("read on server (from %s): %s\n", addr, buffer);
        }

        unsigned long end = DkSystemTimeQuery();
        pal_printf("wall time = %ld\n", end - start);

        int retval;
        DkStreamRead(proc, 0, sizeof(int), &retval, NULL, 0);
        DkStreamDelete(srv, 0);
        DkObjectClose(srv);
    } else {
        PAL_HANDLE cli = DkStreamOpen("udp:127.0.0.1:8000", 0, 0, 0, 0);

        DkStreamGetName(cli, addr, 40);
        pal_printf("client connected on %s\n", addr);

        for (i = 0; i < NTRIES; i++) {
            int bytes = DkStreamWrite(cli, 0, 12, "Hello World", NULL);

            if (!bytes) {
                pal_printf("not able to send to server\n");
                return -1;
            }
        }

        DkObjectClose(cli);

        int retval = 0;
        DkStreamWrite(pal_control.parent_process, 0, sizeof(int), &retval, NULL);
    }

    return 0;
}
