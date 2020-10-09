/* use `-fno-builtin` compiler option to prevent nearbyint and fesetround being optimized out */

#include <err.h>
#include <fenv.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int rounding_modes[] = {FE_TONEAREST, FE_UPWARD, FE_DOWNWARD, FE_TOWARDZERO};

static void* thread_fp(void* arg) {
    printf("child: 42.5 = %.1f, -42.5 = %.1f\n", nearbyint(42.5), nearbyint(-42.5));
    return NULL;
}

int main(int argc, char* argv[]) {
    int ret;

    int mode = FE_TONEAREST;
    if (argc > 1) {
        mode = atoi(argv[1]);
        if (mode > sizeof(rounding_modes)/sizeof(rounding_modes[0]) - 1) {
            errx(EXIT_FAILURE, "run with single argument <rounding mode: one of 0..%lu>",
                 sizeof(rounding_modes)/sizeof(rounding_modes[0]) - 1);
        }
    }

    ret = fesetround(rounding_modes[mode]);
    if (ret)
        err(EXIT_FAILURE, "fesetround failed");

    pthread_t thread;
    ret = pthread_create(&thread, NULL, thread_fp, NULL);
    if (ret)
        err(EXIT_FAILURE, "pthread_create failed");

    ret = pthread_join(thread, NULL);
    if (ret)
        err(EXIT_FAILURE, "pthread_join failed");

    printf("parent: 42.5 = %.1f, -42.5 = %.1f\n", nearbyint(42.5), nearbyint(-42.5));
    return 0;
}
