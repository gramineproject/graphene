/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <linux/futex.h>
#include <assert.h>

// 64kB stack
#define FIBER_STACK 1024 * 64
#define THREADS 2
static int myfutex = 0;
struct atomic_int {
    volatile int counter;
};
static struct atomic_int my_counter;
    
static inline void atomic_inc (struct atomic_int * v)
{
    asm volatile( "lock; incl %0"
                 : "+m" (v->counter));
}

static int
futex(int *uaddr, int futex_op, int val,
      const struct timespec *timeout, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val,
                   timeout, uaddr, val3);
}

int thread_function (void * argument)
{
    int *ptr = (int *) argument;
    int rv;
    atomic_inc(&my_counter);

    // Sleep on the futex
    rv = futex(&myfutex, FUTEX_WAIT_BITSET, 0, NULL, NULL, *ptr);
    assert(rv == 0);
    //printf("child thread %d awakened\n", getpid());
    return 0;
}

int main (int argc, const char ** argv)
{
    void * stacks[THREADS];
    pid_t pids[THREADS];
    int varx[THREADS];
    my_counter.counter = 0;

    for (int i = 0; i < THREADS; i++) {

        varx[i] = (1 << i);
        
        // Allocate the stack
        stacks[i] = malloc(FIBER_STACK);
        if (stacks[i] == 0) {
            perror("malloc: could not allocate stack");
            _exit(1);
        }
        
        // Call the clone system call to create the child thread
        pids[i] = clone(&thread_function, (void *) stacks[i] + FIBER_STACK,
                        CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM,
                        &varx[i]);
        
        //printf("clone() creates new thread %d\n", pids[i]);
        
        if (pids[i] == -1) {
            perror("clone");
            _exit(2);
        }
    }
    
    // Make sure the threads are sleeping
    do {
        sleep(1); 
    } while(my_counter.counter != THREADS);
    
    printf("Waking up kiddos\n");
    /* Wake in reverse order */
    for (int i = THREADS-1; i >= 0; i--) {
        pid_t pid;
        int rv;
        int var = (1 << i);

        // Wake up the thread
        rv = futex(&myfutex, FUTEX_WAKE_BITSET, 1, NULL, NULL, var);
        assert(rv == 1);

        // Wait for the child thread to exit
        pid = waitpid(pids[i], NULL, __WALL);
        if (pid == -1) {
            perror("waitpid");
            _exit(3);
        }

        // Free the stack
        free(stacks[i]);
    }

    printf("Woke all kiddos\n");

    return 0;
}
