/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

const char * message;

void SIGBUS_handler (int sig)
{
    puts(message);
    exit(0);
}

int main (int argc, const char ** argv)
{
    int rv;

    /* Initalization: create a 1025-byte file */

    FILE * fp = fopen("testfile","w+");
    if (!fp) {
        perror("fopen"); return 1;
    }

    rv = ftruncate(fileno(fp), 1024);
    if (rv) {
        perror ("ftruncate"); return 1;
    }

    volatile unsigned char * a
        = mmap(NULL, 9162, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FILE, fileno(fp), 0);
    if (a == MAP_FAILED) {
        perror("mmap"); return 1;
    }

    a[1023] = 0xff;
    a[4095] = 0xff;

    asm volatile ("nop" ::: "memory");

    int pid = fork();
    if (pid == -1) {
        perror("fork"); return 1;
    }
    if (pid != 0) {
        rv = waitpid(pid, NULL, 0);
        if (rv == -1) {
            perror("waitpid"); return 1;
        }
    }

    asm volatile ("nop" ::: "memory");

    a[   0] = 0xff;
    printf(pid == 0 ? "mmap test 1 passed\n" : "mmap test 6 passed\n");
    a[1024] = 0xff;
    printf(pid == 0 ? "mmap test 2 passed\n" : "mmap test 7 passed\n");

    asm volatile ("nop" ::: "memory");

    if (pid == 0) {
        if (a[1023] == 0xff)
            printf("mmap test 3 passed\n");
        if (a[4095] == 0xff)
            printf("mmap test 4 passed\n");
    }

    asm volatile ("nop" ::: "memory");

    if (signal(SIGBUS, SIGBUS_handler) == SIG_ERR) {
        perror("signal"); return 1;
    }

    message = pid == 0 ? "mmap test 5 passed\n" : "mmap test 8 passed\n";
    a[4096] = 0xff;

    if (signal(SIGBUS, SIG_DFL) == SIG_ERR) {
        perror("signal"); return 1;
    }

    return 0;
}
