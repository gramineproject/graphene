#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    dup2(1, 255);
    close(1);
    FILE* new_stdout = fdopen(255, "a");
    fprintf(new_stdout, "Hello World!\n");
    fflush(new_stdout);
    return 0;
}
