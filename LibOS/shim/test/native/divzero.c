#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

void handler(int signal) {
    printf("get signal: %d\n", signal);
    exit(0);
}

int main(void) {
    int i = 0;
    signal(SIGFPE, &handler);
    i = 1 / i;
    return 0;
}
