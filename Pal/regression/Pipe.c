#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    char buffer1[20] = "Hello World 1";
    char buffer2[20] = "Hello World 2";
    char buffer3[20];
    char buffer4[20];
    int ret;

    PAL_HANDLE pipe1 = DkStreamOpen("pipe.srv:1", PAL_ACCESS_RDWR, 0, 0, 0);

    if (pipe1) {
        pal_printf("Pipe Creation 1 OK\n");

        // DEP 10/24/16: Try to read some attributes of the pipe
        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQueryByHandle(pipe1, &attr)) {
            pal_printf("Failed to get any attributes from the pipesrv\n");
            return -1;
        } else {
            pal_printf("Pipe Attribute Query 1 on pipesrv returned OK\n");
        }
        // DEP: would be nice to sanity check the attributes.
        // Job for another day...

        PAL_HANDLE pipe2 = DkStreamOpen("pipe:1", PAL_ACCESS_RDWR, 0, 0, 0);

        if (pipe2) {
            PAL_HANDLE pipe3 = DkStreamWaitForClient(pipe1);

            if (pipe3) {
                pal_printf("Pipe Connection 1 OK\n");

                ret = DkStreamWrite(pipe3, 0, 20, buffer1, NULL);
                if (ret > 0)
                    pal_printf("Pipe Write 1 OK\n");

                ret = DkStreamRead(pipe2, 0, 20, buffer3, NULL, 0);
                if (ret > 0)
                    pal_printf("Pipe Read 1: %s\n", buffer3);

                ret = DkStreamWrite(pipe2, 0, 20, buffer2, NULL);
                if (ret > 0)
                    pal_printf("Pipe Write 2 OK\n");

                ret = DkStreamRead(pipe3, 0, 20, buffer4, NULL, 0);
                if (ret > 0)
                    pal_printf("Pipe Read 2: %s\n", buffer4);
            }
        }
    }

    return 0;
}
