#include "hex.h"

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main() {
    char x[] = {0xde, 0xad, 0xbe, 0xef};
    char y[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
    pal_printf("Hex test 1 is %s\n", ALLOCA_BYTES2HEXSTR(x));
    pal_printf("Hex test 2 is %s\n", ALLOCA_BYTES2HEXSTR(y));
    return 0;
}
