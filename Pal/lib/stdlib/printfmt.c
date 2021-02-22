/* Implementation of printf console output for user environments.
 *
 * It's intended only for debugging and logging purposes.
 */

#include <stdarg.h>
#include <stdint.h>

#include "api.h"

// Print a number (base <= 16) in reverse order,
// using specified fputch function and associated pointer put_data.
static int printnum(int (*_fputch)(void*, int, void*), void* f, void* put_data,
                    unsigned long long num, unsigned base, int width, int padc) {
    // first recursively print all preceding (more significant) digits
    if (num >= base) {
        if (printnum(_fputch, f, put_data, num / base, base, width - 1, padc) == -1)
            return -1;
    } else {
        // print any needed pad characters before first digit
        while (--width > 0)
            if ((*_fputch)(f, padc, put_data) == -1)
                return -1;
    }

    // then print this (the least significant) digit
    if ((*_fputch)(f, "0123456789abcdef"[num % base], put_data) == -1)
        return -1;

    return 0;
}

// Get an unsigned integer of various possible sizes from a varargs list, depending on the lflag
// parameter.
// Defined as macro because it alters `ap` and passing `va_list` by pointer turns out to be tricky
// - on some archs it's defined as array and then `&ap` has a different type than `va_list*` if `ap`
// is a function parameter.
#define GET_UINT(ap, lflag)          \
    (((lflag) >= 2)                  \
    ? va_arg(ap, unsigned long long) \
    : (lflag)                        \
        ? va_arg(ap, unsigned long)  \
        : va_arg(ap, unsigned int))

// Same as GET_UINT but signed
#define GET_INT(ap, lflag)  \
    (((lflag) >= 2)         \
    ? va_arg(ap, long long) \
    : (lflag)               \
        ? va_arg(ap, long)  \
        : va_arg(ap, int))

void vfprintfmt(int (*_fputch)(void*, int, void*), void* f, void* put_data, const char* fmt,
                va_list ap) {
    const char* p;
    int ch;
    unsigned long long num_u;
    long long num_s;
    int base, lflag, width, precision, altflag;
    char padc;

    while (1) {
        while ((ch = (unsigned char)*(fmt++)) != '%') {
            if (ch == '\0')
                return;
            if ((*_fputch)(f, ch, put_data) < 0)
                return;
        }

        // Process a %-escape sequence
        padc      = ' ';
        width     = -1;
        precision = -1;
        lflag     = 0;
        altflag   = 0;
    reswitch:
        switch (ch = *(unsigned char*)(fmt++)) {
            // flag to pad on the right
            case '-':
                padc = ' ';
                goto reswitch;

            // flag to pad with 0's instead of spaces
            case '0':
                padc = '0';
                goto reswitch;

            // width field
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                for (precision = 0;; fmt++) {
                    precision = precision * 10 + ch - '0';
                    ch = *fmt;
                    if (ch < '0' || ch > '9')
                        break;
                }
                goto process_precision;

            case '*':
                precision = va_arg(ap, int);
                goto process_precision;

            case '.':
                if (width < 0)
                    width = 0;
                goto reswitch;

            case '#':
                altflag = 1;
                goto reswitch;

            process_precision:
                if (width < 0) {
                    width = precision;
                    precision = -1;
                }
                goto reswitch;

            // long flag (doubled for long long)
            case 'l':
                lflag++;
                goto reswitch;

            // character
            case 'c':
                if ((*_fputch)(f, va_arg(ap, int), put_data) == -1)
                    return;
                break;

            // string
            case 's':
                if ((p = va_arg(ap, char*)) == NULL)
                    p = "(null)";
                if (width > 0 && padc != '-')
                    for (width -= strnlen(p, precision); width > 0; width--)
                        if ((*_fputch)(f, padc, put_data) == -1)
                            return;
                for (; (ch = *p++) != '\0' && (precision < 0 || --precision >= 0); width--)
                    if (altflag && (ch < ' ' || ch > '~')) {
                        if ((*_fputch)(f, '?', put_data) == -1)
                            return;
                    } else {
                        if ((*_fputch)(f, ch, put_data) == -1)
                            return;
                    }
                for (; width > 0; width--)
                    if ((*_fputch)(f, ' ', put_data) == -1)
                        return;
                break;

            // (signed) decimal
            case 'd':
            case 'i':
                num_s = GET_INT(ap, lflag);
                if (num_s < 0) {
                    if ((*_fputch)(f, '-', put_data) == -1)
                        return;
                    num_u = -(num_s + 1); // This way we evade a potential UB (negation of the
                                          // smallest int value)
                    num_u++;
                } else {
                    num_u = num_s;
                }
                base = 10;
                goto print_unsigned;

            // unsigned decimal
            case 'u':
                num_u = GET_UINT(ap, lflag);
                base = 10;
                goto print_unsigned;

            // (unsigned) octal
            case 'o':
                num_u = GET_UINT(ap, lflag);
                base = 8;
                goto print_unsigned;

            // pointer
            case 'p':
                if ((*_fputch)(f, '0', put_data) == -1)
                    return;
                if ((*_fputch)(f, 'x', put_data) == -1)
                    return;
                num_u = (unsigned long long)(uintptr_t)va_arg(ap, void*);
                base = 16;
                goto print_unsigned;

            // (unsigned) hexadecimal
            case 'x':
                num_u = GET_UINT(ap, lflag);
                base = 16;
            print_unsigned:
                if (printnum(_fputch, f, put_data, num_u, base, width, padc) == -1)
                    return;
                break;

            // escape character
            case '^':
                if ((*_fputch)(f, 0x1b, put_data) == -1)
                    return;
                break;

            // escaped '%' character
            case '%':
                (*_fputch)(f, ch, put_data);
                break;

            // unrecognized escape sequence - just print it literally
            default:
                (*_fputch)(f, '%', put_data);
                for (fmt--; fmt[-1] != '%'; fmt--)
                    /* do nothing */;
                break;
        }
    }
}

void fprintfmt(int (*_fputch)(void*, int, void*), void* f, void* put_data, const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintfmt(_fputch, f, put_data, fmt, ap);
    va_end(ap);
}

struct sprintbuf {
    size_t cnt;
    size_t max;
    char* buf;
};

static int sprintputch(void* f, int ch, void* _buf) {
    __UNUSED(f);

    struct sprintbuf* buf = (struct sprintbuf*)_buf;

    if (buf->cnt >= buf->max)
        return -1;

    buf->buf[buf->cnt++] = ch;
    return 0;
}

int vsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {
    struct sprintbuf b = {
        .cnt = 0,
        .max = n,
        .buf = buf,
    };

    if (!buf || n < 1)
        return 0;

    // print the string to the buffer
    vfprintfmt(sprintputch, NULL, &b, fmt, ap);

    // null terminate the buffer
    if (b.cnt < n)
        b.buf[b.cnt] = '\0';

    return b.cnt;
}

int snprintf(char* buf, size_t n, const char* fmt, ...) {
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = vsnprintf(buf, n, fmt, ap);
    va_end(ap);

    return rc;
}
