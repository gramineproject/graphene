#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    char buffer1[20] = "Hello World 1", buffer2[20] = "Hello World 2";
    char buffer3[20], buffer4[20];
    int ret;

    memset(buffer3, 0, 20);
    memset(buffer4, 0, 20);

    PAL_HANDLE tcp1 = DkStreamOpen("tcp.srv:127.0.0.1:3000", PAL_ACCESS_RDWR, 0, 0, 0);

    if (tcp1) {
        pal_printf("TCP Creation 1 OK\n");

        PAL_HANDLE tcp2 = DkStreamOpen("tcp:127.0.0.1:3000", PAL_ACCESS_RDWR, 0, 0, 0);

        if (tcp2) {
            PAL_HANDLE tcp3 = DkStreamWaitForClient(tcp1);

            if (tcp3) {
                pal_printf("TCP Connection 1 OK\n");

                ret = DkStreamWrite(tcp3, 0, 20, buffer1, NULL);
                if (ret > 0)
                    pal_printf("TCP Write 1 OK\n");

                ret = DkStreamRead(tcp2, 0, 20, buffer3, NULL, 0);
                if (ret > 0)
                    pal_printf("TCP Read 1: %s\n", buffer3);

                ret = DkStreamWrite(tcp2, 0, 20, buffer2, NULL);
                if (ret > 0)
                    pal_printf("TCP Write 2 OK\n");

                ret = DkStreamRead(tcp3, 0, 20, buffer4, NULL, 0);
                if (ret > 0)
                    pal_printf("TCP Read 2: %s\n", buffer4);

                DkObjectClose(tcp3);
            }

            DkObjectClose(tcp2);
        }

        DkStreamDelete(tcp1, 0);
        DkObjectClose(tcp1);
    }

    PAL_HANDLE udp1 = DkStreamOpen("udp.srv:127.0.0.1:3000", PAL_ACCESS_RDWR, 0, 0, 0);

    if (udp1) {
        pal_printf("UDP Creation 1 OK\n");

        PAL_HANDLE udp2 = DkStreamOpen("udp:127.0.0.1:3000", PAL_ACCESS_RDWR, 0, 0, 0);

        if (udp2) {
            pal_printf("UDP Connection 1 OK\n");

            memset(buffer3, 0, 20);
            memset(buffer4, 0, 20);

            ret = DkStreamWrite(udp2, 0, 20, buffer1, NULL);
            if (ret > 0)
                pal_printf("UDP Write 1 OK\n");

            char uri[20];

            ret = DkStreamRead(udp1, 0, 20, buffer3, uri, 20);
            if (ret > 0)
                pal_printf("UDP Read 1: %s\n", buffer3);

            ret = DkStreamWrite(udp1, 0, 20, buffer2, uri);
            if (ret > 0)
                pal_printf("UDP Write 2 OK\n");

            ret = DkStreamRead(udp2, 0, 20, buffer4, NULL, 0);
            if (ret > 0)
                pal_printf("UDP Read 2: %s\n", buffer4);

            DkObjectClose(udp2);
        }

        PAL_HANDLE udp3 =
            DkStreamOpen("udp:127.0.0.1:3001:127.0.0.1:3000", PAL_ACCESS_RDWR, 0, 0, 0);

        if (udp3) {
            pal_printf("UDP Connection 2 OK\n");

            memset(buffer3, 0, 20);
            memset(buffer4, 0, 20);

            ret = DkStreamWrite(udp3, 0, 20, buffer1, NULL);
            if (ret > 0)
                pal_printf("UDP Write 3 OK\n");

            char uri[20];

            ret = DkStreamRead(udp1, 0, 20, buffer3, uri, 20);
            if (ret > 0)
                pal_printf("UDP Read 3: %s\n", buffer3);

            ret = DkStreamWrite(udp1, 0, 20, buffer2, "udp:127.0.0.1:3001");
            if (ret > 0)
                pal_printf("UDP Write 4 OK\n");

            ret = DkStreamRead(udp3, 0, 20, buffer4, NULL, 0);
            if (ret > 0)
                pal_printf("UDP Read 4: %s\n", buffer4);

            DkObjectClose(udp3);
        }

        DkStreamDelete(udp1, 0);
        DkObjectClose(udp1);
    }

    return 0;
}
