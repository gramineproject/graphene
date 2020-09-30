#define _GNU_SOURCE
#include <emmintrin.h> // Intel SSE2 (XMM) intrinsics
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

static atomic_int sigfpe_ctr = 0;

static void sigfpe_handler(int signum, siginfo_t* si, void* uc) {
    printf("Got signal %d\n", signum);
    if (signum == SIGFPE) {
        ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RBX] = 1; /* fix divisor */
        sigfpe_ctr++;
    }
}

int main(int argc, char** argv) {
    int ret;

    const struct sigaction act = {
        .sa_sigaction = sigfpe_handler,
        .sa_flags = SA_SIGINFO,
    };

    ret = sigaction(SIGFPE, &act, NULL);
    if (ret < 0) {
        err(EXIT_FAILURE, "sigaction failed");
    }

    int16_t in[8] __attribute__((aligned(16))) = {0, 1, 2, 3, 4, 5, 6, 7};
    int16_t out[8] __attribute__((aligned(16))) = {0};

    __asm__ volatile("pxor %%xmm0, %%xmm0\n"
                     "movdqa %0, %%xmm0"
                     :: "m"(in) : "xmm0", "memory");

    __asm__ volatile("movq $1, %%rax\n"
                     "cqo\n"
                     "movq $0, %%rbx\n"
                     "divq %%rbx\n"
                     ::: "rax", "rbx", "rdx", "cc", "memory");

    __asm__ volatile("movdqa %%xmm0, %0\n"
                     "pxor %%xmm0, %%xmm0\n"
                     :"=m"(out) :: "xmm0", "memory");

    for (int i = 0; i < 8; i++) {
        if (out[i] != i) {
            errx(EXIT_FAILURE, "XSAVE state (XMM registers' values) was lost!");
        }
    }

    if (sigfpe_ctr != 1) {
        errx(EXIT_FAILURE, "Expected exactly 1 SIGFPE signal but received %d!", sigfpe_ctr);
    }

    printf("Got %d SIGFPE signal(s)\n", sigfpe_ctr);
    puts("TEST OK");
    exit(EXIT_SUCCESS);
}
