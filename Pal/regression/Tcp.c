#include "api.h"
#include "pal.h"
#include "pal_debug.h"

#define PORT   8000
#define NTRIES 10

int main(int argc, char** argv) {
    char addr[40];
    int i;

    if (argc == 1) {
        unsigned long time = DkSystemTimeQuery();
        pal_printf("start time = %lu\n", time);

        char time_arg[24];
        snprintf(time_arg, 24, "%ld", time);

        const char* newargs[4] = {"Tcp", time_arg, NULL};

        PAL_HANDLE srv = DkStreamOpen("tcp.srv:127.0.0.1:8000", 0, 0, 0, 0);

        if (!srv) {
            pal_printf("not able to create server\n");
            return -1;
        }

        DkStreamGetName(srv, addr, 40);
        pal_printf("server bound on %s\n", addr);

        PAL_HANDLE proc = DkProcessCreate("file:Tcp", newargs);

        for (i = 0; i < NTRIES; i++) {
            PAL_HANDLE cli = DkStreamWaitForClient(srv);

            if (!cli) {
                pal_printf("not able to accept client\n");
                return -1;
            }

            DkStreamGetName(cli, addr, 40);
            pal_printf("client accepted on %s\n", addr);

            int bytes = DkStreamWrite(cli, 0, 12, "Hello World", NULL);

            if (!bytes) {
                pal_printf("not able to send to client\n");
                return -1;
            }

            DkObjectClose(cli);
        }

        int retval;
        DkStreamRead(proc, 0, sizeof(int), &retval, NULL, 0);
        DkStreamDelete(srv, 0);
        DkObjectClose(srv);
    } else {
        for (i = 0; i < NTRIES; i++) {
            PAL_HANDLE cli = DkStreamOpen("tcp:127.0.0.1:8000", 0, 0, 0, 0);

            if (!cli) {
                pal_printf("not able to create client\n");
                return -1;
            }

            DkStreamGetName(cli, addr, 40);
            pal_printf("client connected on %s\n", addr);

            char buffer[12];
            int bytes = DkStreamRead(cli, 0, 12, buffer, NULL, 0);

            if (!bytes) {
                pal_printf("not able to receive from server\n");
                return -1;
            }

            pal_printf("read from server: %s\n", buffer);

            DkStreamDelete(cli, 0);
            DkObjectClose(cli);
        }

        unsigned long end = DkSystemTimeQuery();
        pal_printf("end time = %lu\n", end);

        unsigned long start = atol(argv[1]);
        pal_printf("wall time = %ld\n", end - start);

        int retval = 0;
        DkStreamWrite(pal_control.parent_process, 0, sizeof(int), &retval, NULL);
    }

    return 0;
}
