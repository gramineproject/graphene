#include <linux/time.h>

#include "api.h"
#include "cpu.h"
#include "linux_utils.h"
#include "sysdep-arch.h"

void time_get_now_plus_ns(struct timespec* ts, uint64_t val) {
    /* This can only fail if arguments are invalid. */
    int ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_MONOTONIC, ts);
    if (ret < 0) {
        die_or_inf_loop();
    }

    ts->tv_sec += val / TIME_NS_IN_S;
    ts->tv_nsec += val % TIME_NS_IN_S;
    if ((uint64_t)ts->tv_nsec >= TIME_NS_IN_S) {
        ts->tv_nsec -= TIME_NS_IN_S;
        ts->tv_sec += 1;
    }
}

int64_t time_ns_diff_from_now(struct timespec* ts) {
    struct timespec time_now;
    /* This can only fail if arguments are invalid. */
    int ret = INLINE_SYSCALL(clock_gettime, 2, CLOCK_MONOTONIC, &time_now);
    if (ret < 0) {
        die_or_inf_loop();
    }

    int64_t diff = (ts->tv_sec - time_now.tv_sec) * TIME_NS_IN_S;
    diff += ts->tv_nsec - time_now.tv_nsec;
    return diff;
}
