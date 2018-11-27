#include <stdlib.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
    for (int i = 0 ; i < 100000 ; i++) {
        malloc(16);
        malloc(32);
        malloc(64);
        malloc(128);
        malloc(256);
        malloc(512);
    }
    return 0;
}
