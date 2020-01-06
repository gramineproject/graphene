#include <errno.h>
#include <shim_table.h>

int main(int argc, char** argv) {
    pid_t pid = shim_vfork();

    if (pid < 0) {
        shim_write(1, "failed on fork\n", 15);
        shim_exit_group(-1);
    }

    if (pid == 0) {
        shim_write(1, "Hello, Dad!\n", 12);
    } else {
        shim_write(1, "Hello, Kid!\n", 12);
    }

    shim_exit_group(0);
    return 1;  // should not reach here.
}
