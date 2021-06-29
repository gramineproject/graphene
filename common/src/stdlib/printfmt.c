/* Implementation of printf console output for user environments.
 *
 * It's intended only for debugging and logging purposes.
 */

#include <stdarg.h>
#include <stdint.h>

#include "assert.h"
#include "api.h"
#include "log.h"

#undef vsnprintf
#undef snprintf

// Print a number (base <= 16) in reverse order,
// using specified fputch function and associated pointer put_data.
static int printnum(int (*_fputc)(char c, void* arg), void* arg, unsigned long long num,
                    unsigned base, int width, char padc) {
    int ret;

    assert(base <= 16);

    // first recursively print all preceding (more significant) digits
    if (num >= base) {
        if ((ret = printnum(_fputc, arg, num / base, base, width - 1, padc)) < 0)
            return ret;
    } else {
        // print any needed pad characters before first digit
        while (--width > 0)
            if ((ret = _fputc(padc, arg)) < 0)
                return ret;
    }

    // then print this (the least significant) digit
    if ((ret = _fputc("0123456789abcdef"[num % base], arg)) < 0)
        return ret;

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


int vfprintfmt(int (*_fputc)(char c, void* arg), void* arg, const char* fmt, va_list ap) {
    const char* p;
    int ch;
    unsigned long long num_u;
    long long num_s;
    int base, lflag, width, precision, altflag;
    char padc;
    int ret;

    while (1) {
        while ((ch = (unsigned char)*(fmt++)) != '%') {
            if (ch == '\0')
                return 0;
            if ((ret = _fputc(ch, arg)) < 0)
                return ret;
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
                if ((ret = _fputc(va_arg(ap, int), arg)) < 0)
                    return ret;
                break;

            // string
            case 's':
                if ((p = va_arg(ap, char*)) == NULL)
                    p = "(null)";
                if (width > 0 && padc != '-')
                    for (width -= strnlen(p, precision); width > 0; width--)
                        if ((ret = _fputc(padc, arg)) < 0)
                            return ret;
                for (; (ch = *p++) != '\0' && (precision < 0 || --precision >= 0); width--)
                    if (altflag && (ch < ' ' || ch > '~')) {
                        if ((ret = _fputc('?', arg)) < 0)
                            return ret;
                    } else {
                        if ((ret = _fputc(ch, arg)) < 0)
                            return ret;
                    }
                for (; width > 0; width--)
                    if ((ret = _fputc(' ', arg)) < 0)
                        return ret;
                break;

            // (signed) decimal
            case 'd':
            case 'i':
                num_s = GET_INT(ap, lflag);
                if (num_s < 0) {
                    if ((ret = _fputc('-', arg)) < 0)
                        return ret;
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
                if ((ret = _fputc('0', arg)) < 0)
                    return ret;
                if ((ret = _fputc('x', arg)) < 0)
                    return ret;
                num_u = (unsigned long long)(uintptr_t)va_arg(ap, void*);
                base = 16;
                goto print_unsigned;

            // (unsigned) hexadecimal
            case 'x':
                num_u = GET_UINT(ap, lflag);
                base = 16;
            print_unsigned:
                if ((ret = printnum(_fputc, arg, num_u, base, width, padc)) < 0)
                    return ret;
                break;

            // escape character
            case '^':
                if ((ret = _fputc(0x1b, arg)) < 0)
                    return ret;
                break;

            // escaped '%' character
            case '%':
                if ((ret = _fputc(ch, arg)) < 0)
                    return ret;
                break;

            // '%' at the end of string - just print the %
            case '\0':
                if ((ret = _fputc('%', arg)) < 0)
                    return ret;
                return 0;

            // unrecognized escape sequence - just print it literally
            default:
                if ((ret = _fputc('%', arg)) < 0)
                    return ret;
                if ((ret = _fputc(ch, arg)) < 0)
                    return ret;
                break;
        }
    }
    return 0;
}

struct sprintbuf {
    size_t cnt;
    size_t str_end;
    size_t buf_size;
    char* buf;
};

static int sprintputch(char ch, void* arg) {
    struct sprintbuf* buf = arg;

    if (buf->cnt + 1 < buf->buf_size) { // leave one byte for the null terminator
        buf->buf[buf->cnt] = ch;
        buf->str_end = buf->cnt + 1;
    }
    buf->cnt++;
    return 0;
}

int vsnprintf(char* buf, size_t buf_size, const char* fmt, va_list ap) {
    struct sprintbuf b = {
        .cnt = 0,
        .str_end = 0,
        .buf_size = buf_size,
        .buf = buf,
    };

    vfprintfmt(sprintputch, &b, fmt, ap);

    if (buf_size > 0) {
        assert(b.str_end < buf_size);
        b.buf[b.str_end] = '\0';
    }

    return b.cnt;
}

int __vsnprintf_chk(char* buf, size_t buf_size, int flag, size_t real_size, const char* fmt,
                    va_list ap) {
    __UNUSED(flag);
    if (buf_size > real_size) {
        log_always("vsnprintf() check failed");
        abort();
    }
    return vsnprintf(buf, buf_size, fmt, ap);
}

int snprintf(char* buf, size_t buf_size, const char* fmt, ...) {
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = vsnprintf(buf, buf_size, fmt, ap);
    va_end(ap);

    return rc;
}

int __snprintf_chk(char* buf, size_t buf_size, int flag, size_t real_size, const char* fmt, ...) {
    __UNUSED(flag);
    if (buf_size > real_size) {
        log_always("vsnprintf() check failed");
        abort();
    }

    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = vsnprintf(buf, buf_size, fmt, ap);
    va_end(ap);

    return rc;
}

int buf_puts(struct print_buf* buf, const char* str) {
    for (; *str; str++) {
        int ret;
        if ((ret = buf_putc(buf, *str)) < 0)
            return ret;
    }
    return 0;

}

int buf_putc(struct print_buf* buf, char c) {
    if (buf->pos == ARRAY_SIZE(buf->data)) {
        int ret;
        if ((ret = buf_flush(buf)) < 0)
            return ret;
    }
    assert(buf->pos < ARRAY_SIZE(buf->data));
    buf->data[buf->pos++] = c;
    return 0;
}

static int __buf_putc(char c, void* arg) {
    return buf_putc(arg, c);
}

int buf_flush(struct print_buf* buf) {
    int ret;
    if (buf->pos > 0) {
        if ((ret = buf->buf_write_all(&buf->data[0], buf->pos, buf->arg)) < 0)
            return ret;
        buf->pos = 0;
    }
    return 0;
}

int buf_vprintf(struct print_buf* buf, const char* fmt, va_list ap) {
    return vfprintfmt(__buf_putc, buf, fmt, ap);
}

int buf_printf(struct print_buf* buf, const char* fmt, ...) {
    va_list ap;
    int rc;

    va_start(ap, fmt);
    rc = buf_vprintf(buf, fmt, ap);
    va_end(ap);

    return rc;
}
