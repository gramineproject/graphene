/* This Hello World demostrate a simple multithread program */

#define DO_BENCH    1

#include "pal.h"
#include "pal_debug.h"

int main (int argc, char ** argv)
{
    if (argc == 1) {
        char id[2] = { '0', 0 };
        const char * newargs[] = { "Broadcast", id, NULL };
        PAL_HANDLE proc[4];
        int i;

        for (i = 0 ; i < 4 ; i++) {
            id[0] = '0' + i + 1;
            proc[i] = DkProcessCreate ("file:Broadcast", newargs);
        }

        DkThreadDelayExecution(1000000);
        DkStreamWrite(pal_control.broadcast_stream, 0, 12, "Hello World", NULL);

        for (i = 0 ; i < 4 ; i++) {
            char byte;
            DkStreamRead(proc[i], 0, 1, &byte, NULL, 0);
            pal_printf("process %d exited\n", i + 1);
        }
    } else {
        char bytes[12];

        pal_printf("process %s started\n", argv[1]);

        DkStreamRead(pal_control.broadcast_stream, 0, 12, bytes, NULL, 0);

        pal_printf("process %s received: %s\n", argv[1], bytes);

        DkStreamWrite(pal_control.parent_process, 0, 1, "0", NULL);
    }

    return 0;
}

