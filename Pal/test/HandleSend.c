/* This Hello World demostrate a simple multithread program */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv) {
    int nsend = 5, i;
    PAL_HANDLE handles[nsend];

    if (argc == 1) {
        /* parent */
        pal_printf("Parent: Executing the program\n");

        const char* args[3] = {"HandleSend", "child", NULL};
        char* data          = "Hello World";
        char content[20];
        char uri[80];
        PAL_HANDLE child;
        int bytes;

        pal_printf("Parent: Creating handles\n");

        // Sending pipe handle
        handles[0] = DkStreamOpen("pipe.srv:012", PAL_ACCESS_RDWR, 0, PAL_CREATE_TRY, 0);
        if (!handles[0]) {
            pal_printf("Parent: DkStreamOpen for pipe failed\n");
            goto out;
        }

        // Sending pipe handle
        handles[1] = DkStreamOpen("udp:127.0.0.1:8000", PAL_ACCESS_RDWR, 0, PAL_CREATE_TRY, 0);
        if (!handles[1]) {
            pal_printf("Parent: DkStreamOpen for socket failed\n");
            goto out;
        }

        for (i = 2; i < nsend; i++) {
            snprintf(uri, 80, "file:test_file_%d", i - 2);

            handles[i] = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0600, PAL_CREATE_TRY, 0);
            if (!handles[i]) {
                pal_printf("Parent: DkStreamOpen failed\n");
                goto out;
            }

            DkStreamSetLength(handles[i], 0);
        }

        for (i = 0; i < nsend; i++) {
            /* do some write */
            snprintf(content, sizeof(content), "%s%d", data, i);

            bytes = DkStreamWrite(handles[i], 0, sizeof(content), content, NULL);
            if (!bytes) {
                pal_printf("Parent: DKStreamWrite failed\n");
                goto out;
            }

            DkStreamFlush(handles[i]);
        }

        pal_printf("Parent: Forking child\n");
        child = DkProcessCreate("file:HandleSend", args);

        if (!child) {
            pal_printf("Parent: Failed creating process\n");
            DkProcessExit(1);
        }

        for (i = 0; i < nsend; i++) {
            pal_printf("Parent: Sending Handle %d\n", i);

            if (!DkSendHandle(child, handles[i])) {
                pal_printf("Send handle failed\n");
                goto out;
            }

            DkObjectClose(handles[i]);
        }

        pal_printf("Parent: Finished execution\n");

        DkObjectClose(child);
    } else {
        /* child */
        PAL_HANDLE parent = pal_control.parent_process;

        for (i = 0; i < nsend; i++) {
            pal_printf("Child: Receiving Handle %d\n", i);
            handles[i] = DkReceiveHandle(parent);

            if (!handles[i]) {
                pal_printf("Child: Failed receiving handle\n");
                DkProcessExit(1);
            }
        }

        pal_printf("Child: Reading the handles\n");
        for (i = 0; i < nsend; i++) {
            /* do some read */
            pal_printf("Child: Handle %d Type ", i);
            char data[20];

            switch (PAL_GET_TYPE(handles[i])) {
                case pal_type_file:
                    if ((DkStreamRead(handles[i], 0, 20, data, NULL, 0)))
                        pal_printf("File Data: %s\n", data);
                    else
                        pal_printf("Couldn't read\n");
                    break;
                case pal_type_pipesrv:
                    pal_printf("Pipe\n");
                    break;
                case pal_type_udp:
                    pal_printf("Udp\n");
                    break;
                default:
                    pal_printf("Unknown\n");
            }

            DkObjectClose(handles[i]);
        }

        pal_printf("Child: Finished execution\n\n");

        DkObjectClose(parent);
    }

out:
    for (i = 0; i < nsend; i++) {
        DkObjectClose(handles[i]);
    }

    return 0;
}
