#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

void handler (int signal)
{
    printf("alarm goes off\n");
}

int main(int argc, char ** argv)
{
    signal(SIGALRM, &handler);
    alarm(1);
    sleep(3);
    return 0;
}
