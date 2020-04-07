#include "pal.h"
#include "pal_debug.h"

char str[13] = "Hello World\n";

int main(int argc, char** argv, char** envp) {
    pal_printf("start program: %s\n", pal_control.executable);

    PAL_HANDLE out = DkStreamOpen("dev:tty", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (out == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    int bytes = DkStreamWrite(out, 0, sizeof(str) - 1, str, NULL);

    if (bytes < 0) {
        pal_printf("DkStreamWrite failed\n");
        return -1;
    }

    DkObjectClose(out);
    return 0;
}
