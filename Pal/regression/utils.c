#include "api.h"
#include "pal.h"

// pal_printf() is required by PAL regression tests.
static int buf_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    DkDebugLog((PAL_PTR)str, size);
    return 0;
}

static void log_vprintf(const char* fmt, va_list ap) {
    struct print_buf buf = INIT_PRINT_BUF(buf_write_all);
    buf_vprintf(&buf, fmt, ap);
    buf_flush(&buf);
}

void __attribute__((format(printf, 1, 2))) pal_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

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
