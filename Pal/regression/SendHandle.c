/* This Hello World demostrate a simple multithread program */

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv) {
    PAL_HANDLE handles[3];

    if (argc == 2 && !memcmp(argv[1], "Child", 6)) {
        for (int i = 0; i < 3; i++) {
            handles[i] = DkReceiveHandle(pal_control.parent_process);
            if (handles[i])
                pal_printf("Receive Handle OK\n");
        }

        char buffer[20];

        for (int i = 0; i < 3; i++) {
            if (!handles[i])
                continue;

            memset(buffer, 0, 20);

            switch (PAL_GET_TYPE(handles[i])) {
                case pal_type_pipesrv: {
                    PAL_HANDLE pipe = DkStreamWaitForClient(handles[i]);

                    if (pipe) {
                        if (DkStreamRead(pipe, 0, 20, buffer, NULL, 0))
                            pal_printf("Receive Pipe Handle: %s\n", buffer);

                        DkObjectClose(pipe);
                    }

                    break;
                }

                case pal_type_udpsrv: {
                    char uri[20];

                    if ((DkStreamRead(handles[i], 0, 20, buffer, &uri, 20)))
                        pal_printf("Receive Socket Handle: %s\n", buffer);

                    break;
                }

                case pal_type_file:
                    if (DkStreamRead(handles[i], 0, 20, buffer, NULL, 0))
                        pal_printf("Receive File Handle: %s\n", buffer);

                    break;

                default:
                    break;
            }

            DkObjectClose(handles[i]);
        }
    } else {
        const char* args[3] = {"SendHandle", "Child", NULL};

        PAL_HANDLE child = DkProcessCreate("file:SendHandle", args);

        if (child) {
            // Sending pipe handle
            handles[0] = DkStreamOpen("pipe.srv:1", PAL_ACCESS_RDWR, 0, PAL_CREATE_TRY, 0);

            if (handles[0]) {
                pal_printf("Send Handle OK\n");

                if (DkSendHandle(child, handles[0])) {
                    DkObjectClose(handles[0]);
                    PAL_HANDLE pipe = DkStreamOpen("pipe:1", PAL_ACCESS_RDWR, 0, 0, 0);
                    if (pipe) {
                        DkStreamWrite(pipe, 0, 20, "Hello World", NULL);
                        DkObjectClose(pipe);
                    }
                } else {
                    DkObjectClose(handles[0]);
                }
            }

            // Sending udp handle
            handles[1] =
                DkStreamOpen("udp.srv:127.0.0.1:8000", PAL_ACCESS_RDWR, 0, PAL_CREATE_TRY, 0);

            if (handles[1]) {
                pal_printf("Send Handle OK\n");

                if (DkSendHandle(child, handles[1])) {
                    DkObjectClose(handles[1]);
                    PAL_HANDLE socket =
                        DkStreamOpen("udp:127.0.0.1:8000", PAL_ACCESS_RDWR, 0, 0, 0);
                    if (socket) {
                        DkStreamWrite(socket, 0, 20, "Hello World", NULL);
                        DkObjectClose(socket);
                    }
                } else {
                    DkObjectClose(handles[1]);
                }
            }

            handles[2] = DkStreamOpen("file:to_send.tmp", PAL_ACCESS_RDWR, 0600, PAL_CREATE_TRY, 0);

            if (handles[2]) {
                pal_printf("Send Handle OK\n");

                DkStreamWrite(handles[2], 0, 20, "Hello World", NULL);
                DkStreamSetLength(handles[2], 4096);

                DkSendHandle(child, handles[2]);
                DkObjectClose(handles[2]);
            }
        }

        DkObjectClose(child);
    }

    return 0;
}
