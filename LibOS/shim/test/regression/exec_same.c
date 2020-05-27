#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <unistd.h>

static char* g_argv0 = NULL;
static char** g_argv = NULL;

static noreturn void do_exec(void) {
    execv(g_argv0, g_argv);
    perror("execve failed");
    exit(1);
}

static void* thread_func(void* arg) {
    do_exec();
    return arg;
}

int main(int argc, char** argv) {
    if (argc <= 0) {
        return 1;
    } else if (argc == 1) {
        return 0;
    }

    puts(argv[1]);
    fflush(stdout);

    argv[1] = argv[0];
    g_argv0 = argv[0];
    g_argv = &argv[1];

    pthread_t th;

    /* Creating another thread and doing a race on execve. Only one thread should survive. */
    if (pthread_create(&th, NULL, thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }

    do_exec();
}
