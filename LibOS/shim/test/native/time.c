#include <stdio.h>
#include <sys/time.h>

int main(int argc, char** argv) {
    struct timeval time;

    int ret = gettimeofday(&time, NULL);

    if (ret < 0) {
        perror("gettimeofday");
        return -1;
    }

    printf("Current timestamp: %ld\n", time.tv_sec);
    return 0;
}
