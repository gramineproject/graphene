#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char* mem = malloc(40);
    sprintf(mem, "Hello world (%s)!\n", argv[0]);
    printf("%s", mem);
    return 0;
}
