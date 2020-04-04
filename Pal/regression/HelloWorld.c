/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

char str[13];

int main(int argc, char** argv, char** envp) {
    pal_printf("start program: %s\n", pal_control.executable);

    PAL_HANDLE out = DkStreamOpen("dev:tty", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (out == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    str[0]  = 'H';
    str[1]  = 'e';
    str[2]  = 'l';
    str[3]  = 'l';
    str[4]  = 'o';
    str[5]  = ' ';
    str[6]  = 'W';
    str[7]  = 'o';
    str[8]  = 'r';
    str[9]  = 'l';
    str[10] = 'd';
    str[11] = '\n';
    str[12] = 0;

    int bytes = DkStreamWrite(out, 0, 12, str, NULL);

    if (bytes < 0) {
        pal_printf("DkStreamWrite failed\n");
        return -1;
    }

    DkObjectClose(out);
    return 0;
}
