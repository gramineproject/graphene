#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    sleep(3);
    printf("Hello world (%s)!\n", argv[0]);
    return 0;
}
