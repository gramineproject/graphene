/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

struct stack_frame {
    struct stack_frame* next;
    void* ret;
};

PAL_HANDLE _fork(void* args) {
    register struct stack_frame* fp __asm__("ebp");
    struct stack_frame* frame = fp;

    if (args == NULL) {
        struct stack_frame cur_frame = *frame;
        pal_printf("return address is %p\n", cur_frame.ret);
        return DkThreadCreate(&_fork, &cur_frame);
    } else {
        struct stack_frame* las_frame = (struct stack_frame*)args;
        pal_printf("(in child) return address is %p\n", las_frame->ret);
        return NULL;
    }
}

int main(int argc, char** argv) {
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE out = DkStreamOpen("dev:tty", PAL_ACCESS_WRONLY, 0, 0, 0);

    if (out == NULL) {
        pal_printf("DkStreamOpen failed\n");
        return -1;
    }

    void* param      = NULL;
    PAL_HANDLE child = _fork(param);

    if (child == NULL) {
        pal_printf("in the child\n");

        char* str = (void*)DkVirtualMemoryAlloc(NULL, 20, 0, PAL_PROT_READ | PAL_PROT_WRITE);
        if (str == NULL) {
            pal_printf("DkVirtualMemoryAlloc failed\n");
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

        DkVirtualMemoryFree(str, 20);
        DkThreadExit(/*clear_child_tid=*/NULL);
    } else {
        pal_printf("in the parent\n");
        DkThreadDelayExecution(3000);
    }

    DkObjectClose(out);

    pal_printf("Leave Main Thread\n");
    return 0;
}
