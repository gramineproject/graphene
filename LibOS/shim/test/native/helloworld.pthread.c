/* a simple helloworld test, with pthread usage */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* print(void* arg) {
    printf("child: pid %d\n", getpid());
    puts((char*)arg);
    return NULL;
}

int main(int argc, char** argv) {
    pthread_t thread;
    printf("parent: pid %d\n", getpid());
    pthread_create(&thread, NULL, print, "Hello World!");
    pthread_join(thread, NULL);
    return 0;
}
