#define _GNU_SOURCE
#include <asm/prctl.h>
#include <malloc.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// 64kB stack
#define FIBER_STACK (1024 * 64)

__thread int mypid = 0;

unsigned long gettls(void) {
    unsigned long tls;
    syscall(__NR_arch_prctl, ARCH_GET_FS, &tls);
    return tls;
}

int thread_function(void* argument) {
    mypid    = getpid();
    int* ptr = (int*)argument;
    printf("in the child: pid (%016lx) = %d\n", (unsigned long)&mypid, mypid);
    printf("in the child: pid = %d\n", getpid());
    printf("in the child: tls = %08lx\n", gettls());
    printf("child thread exiting\n");
    printf("argument passed %d\n", *ptr);
    return 0;
}

int main(int argc, const char** argv) {
    void* stack;
    pid_t pid;
    int varx = 143;

    mypid = getpid();

    printf("in the parent: pid = %d\n", getpid());

    // Allocate the stack
    stack = malloc(FIBER_STACK);
    if (stack == 0) {
        perror("malloc: could not allocate stack");
        _exit(1);
    }

    printf("child_stack: %016lx-%016lx\n", (unsigned long)stack,
           (unsigned long)stack + FIBER_STACK);

    // Call the clone system call to create the child thread
    pid = clone(&thread_function, (void*)stack + FIBER_STACK,
                CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM, &varx);

    printf("clone() creates new thread %d\n", pid);

    if (pid == -1) {
        perror("clone");
        _exit(2);
    }

    // Wait for the child thread to exit
    pid = waitpid(0, NULL, __WALL);
    if (pid == -1) {
        perror("waitpid");
        _exit(3);
    }

    // Free the stack
    free(stack);

    printf("in the parent: pid (%016lx) = %d\n", (unsigned long)&mypid, mypid);
    printf("in the parent: pid = %d\n", getpid());
    printf("in the parent: tls = %08lx\n", gettls());

    return 0;
}
