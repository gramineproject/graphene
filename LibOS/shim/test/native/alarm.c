#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void handler(int signal) {
    printf("alarm goes off\n");
}

int main(int argc, char** argv) {
    signal(SIGALRM, &handler);
    alarm(1);
    sleep(3);
    return 0;
}
