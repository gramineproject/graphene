#include "api.h"
#include "pal.h"
#include "pal_regression.h"

// Required by asserts and _FORTIFY_SOURCE.
void __attribute__((format(printf, 1, 2))) warn(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

// Required by asserts and _FORTIFY_SOURCE.
noreturn void __abort(void) {
    warn("ABORTED\n");
    // ENOTRECOVERABLE = 131
    DkProcessExit(131);
}
