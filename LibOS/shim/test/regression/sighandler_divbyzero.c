#define _GNU_SOURCE
#include <emmintrin.h> // Intel SSE2 (XMM) intrinsics
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

    if (argc != 1) {
        fprintf(stderr, "no arguments must be supplied to this program\n");
        exit(EXIT_FAILURE);
    }

    const struct sigaction act = {
        .sa_sigaction = sigfpe_handler,
        .sa_flags = SA_SIGINFO,
    };

    ret = sigaction(SIGFPE, &act, NULL);
    if (ret < 0) {
        fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* populate array with 0,1,2,3... via argc (this test expects no command-line options and thus
     * argc == 1); this is to prevent the compiler from optimizing out the XMM logic */
    int16_t a[8] __attribute__((aligned(16)));
    for (int i = 0; i < 8; i++)
        a[i] = argc - 1 + i;
    __m128i xmm_reg = _mm_load_si128((__m128i*)a);
    __asm__ volatile("" ::: "memory");

    __asm__ volatile("movq $1, %%rax\n"
                     "cqo\n"
                     "movq $0, %%rbx\n"
                     "divq %%rbx\n"
                     ::: "rax", "rbx", "rdx", "cc", "memory");

    if (_mm_extract_epi16(xmm_reg, 0) != 0 || _mm_extract_epi16(xmm_reg, 1) != 1 ||
        _mm_extract_epi16(xmm_reg, 2) != 2 || _mm_extract_epi16(xmm_reg, 3) != 3 ||
        _mm_extract_epi16(xmm_reg, 4) != 4 || _mm_extract_epi16(xmm_reg, 5) != 5 ||
        _mm_extract_epi16(xmm_reg, 6) != 6 || _mm_extract_epi16(xmm_reg, 7) != 7) {
        fprintf(stderr, "XSAVE state (XMM registers' values) was lost!\n");
        exit(EXIT_FAILURE);
    }

    __asm__ volatile("" ::: "memory");

    if (sigfpe_ctr != 1) {
        fprintf(stderr, "Expected exactly 1 SIGFPE signal but received %d!\n", sigfpe_ctr);
        exit(EXIT_FAILURE);
    }
    printf("Got %d SIGFPE signal(s)\n", sigfpe_ctr);

    puts("TEST OK");
    exit(EXIT_SUCCESS);
}
