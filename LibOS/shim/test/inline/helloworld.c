#include <shim_table.h>

int main(int argc, char** argv) {
    shim_write(1, "Hello world\n", 12);
    shim_exit_group(0);
    return 1;  // should not reach here.
}
