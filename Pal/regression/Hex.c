#include "pal.h"
#include "pal_debug.h"
#include "api.h"
#include "hex.h"

int main() {
    char x[] = {0xde, 0xad, 0xbe, 0xef};
    char y[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
    pal_printf("Hex test 1 is %s\n", alloca_bytes2hexstr(x));
    pal_printf("Hex test 2 is %s\n", alloca_bytes2hexstr(y));
    return 0;
}
