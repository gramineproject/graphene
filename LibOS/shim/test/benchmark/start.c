#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define OVERHEAD_TIMES 30000

int main(int argc, char** argv, char** envp) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (argc < 2)
        return 1;

    unsigned long long msec1 = atoll(argv[1]);
    unsigned long long msec2 = tv.tv_sec * 1000000ULL + tv.tv_usec;

    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
    for (int j = 0; j < OVERHEAD_TIMES; j++) {
        gettimeofday(&tv, NULL);
    }
    gettimeofday(&tv2, NULL);
    unsigned long long msec3    = tv1.tv_sec * 1000000ULL + tv1.tv_usec;
    unsigned long long msec4    = tv2.tv_sec * 1000000ULL + tv2.tv_usec;
    unsigned long long overhead = (msec4 - msec3) / OVERHEAD_TIMES;

    printf("%llu\n", msec2 - msec1 - overhead);
    return 0;
}
