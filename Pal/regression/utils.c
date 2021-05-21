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

/* The below two functions are used by stack protector's __stack_chk_fail(), _FORTIFY_SOURCE's
 * *_chk() functions and by assert.h's assert() defined in the common library. Thus they might be
 * called by any execution context, including these PAL tests. */
void __attribute__((format(printf, 1, 2))) log_always(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

noreturn void abort(void) {
    DkProcessExit(131); /* ENOTRECOVERABLE = 131 */
}
