/* Implementation of printf console output for user environments.
 *
 * printf is a debugging statement, not a generic output statement.
 * It is very important that it always go to the console, especially when
 * debugging file descriptor code! */

#include <stdarg.h>
#include <stdint.h>

#include "api.h"

// Print a number (base <= 16) in reverse order,
// using specified fputch function and associated pointer putdat.
#if !defined(__i386__)
static int printnum(int (*_fputch)(void*, int, void*), void* f, void* putdat,
                    unsigned long long num, unsigned base, int width, int padc)
#else
static int printnum(int (*_fputch)(void*, int, void*), void* f, void* putdat, unsigned long num,
                    unsigned base, int width, int padc)
#endif
{
    // first recursively print all preceding (more significant) digits
    if (num >= base) {
        if (printnum(_fputch, f, putdat, num / base, base, width - 1, padc) == -1)
            return -1;
    } else {
        // print any needed pad characters before first digit
        while (--width > 0)
            if ((*_fputch)(f, padc, putdat) == -1)
                return -1;
    }

    // then print this (the least significant) digit
    if ((*_fputch)(f, "0123456789abcdef"[num % base], putdat) == -1)
        return -1;

    return 0;
}

// Get an unsigned int of various possible sizes from a varargs list,
// depending on the lflag parameter.
#if !defined(__i386__)
static inline unsigned long long getuint(va_list ap, int lflag)
#else
static inline unsigned long getuint(va_list ap, int lflag)
#endif
{
#if !defined(__i386__)
    if (lflag >= 2)
        return va_arg(ap, unsigned long long);
#endif
    if (lflag)
        return va_arg(ap, unsigned long);
    return va_arg(ap, unsigned int);
}

// Same as getuint but signed - can't use getuint
// because of sign extension
#if !defined(__i386__)
static inline long long getint(va_list ap, int lflag)
#else
static inline long getint(va_list ap, int lflag)
#endif
{
#if !defined(__i386__)
    if (lflag >= 2)
        return va_arg(ap, long long);
#endif
    if (lflag)
        return va_arg(ap, long);
    return va_arg(ap, int);
}

// Main function to format and print a string.
void fprintfmt(int (*_fputch)(void*, int, void*), void* f, void* putdat, const char* fmt, ...);

void vfprintfmt(int (*_fputch)(void*, int, void*), void* f, void* putdat, const char* fmt,
                va_list ap) {
    register const char* p;
    register int ch;
#if !defined(__i386__)
    unsigned long long num;
#else
    unsigned long num;
#endif
    int base, lflag, width, precision, altflag;
    char padc;

    while (1) {
        while ((ch = *(unsigned char*)(fmt++)) != '%') {
            if (ch == '\0')
                return;
            if ((*_fputch)(f, ch, putdat) < 0)
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
                for (precision = 0;; ++fmt) {
                    precision = precision * 10 + ch - '0';
                    ch        = *fmt;
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
                if (width < 0)
                    width = precision, precision = -1;
                goto reswitch;

            // long flag (doubled for long long)
            case 'l':
                lflag++;
                goto reswitch;

            // character
            case 'c':
                if ((*_fputch)(f, va_arg(ap, int), putdat) == -1)
                    return;
                break;

            // string
            case 's':
                if ((p = va_arg(ap, char*)) == NULL)
                    p = "(null)";
                if (width > 0 && padc != '-')
                    for (width -= strnlen(p, precision); width > 0; width--)
                        if ((*_fputch)(f, padc, putdat) == -1)
                            return;
                for (; (ch = *p++) != '\0' && (precision < 0 || --precision >= 0); width--)
                    if (altflag && (ch < ' ' || ch > '~')) {
                        if ((*_fputch)(f, '?', putdat) == -1)
                            return;
                    } else {
                        if ((*_fputch)(f, ch, putdat) == -1)
                            return;
                    }
                for (; width > 0; width--)
                    if ((*_fputch)(f, ' ', putdat) == -1)
                        return;
                break;

            // (signed) decimal
            case 'd':
            case 'i':
                num = getint(ap, lflag);
#if !defined(__i386__)
                if ((long long)num < 0) {
                    if ((*_fputch)(f, '-', putdat) == -1)
                        return;
                    num = -(long long)num;
                }
#else
                if ((long)num < 0) {
                    if ((*_fputch)(f, '-', putdat) == -1)
                        return;
                    num = -(long)num;
                }
#endif
                base = 10;
                goto number;

            // unsigned decimal
            case 'u':
                num  = getuint(ap, lflag);
                base = 10;
                goto number;

            // (unsigned) octal
            case 'o':
                // Replace this with your code.
                num  = getuint(ap, lflag);
                base = 8;
                goto number;

            // pointer
            case 'p':
                if ((*_fputch)(f, '0', putdat) == -1)
                    return;
                if ((*_fputch)(f, 'x', putdat) == -1)
                    return;
#if !defined(__i386__)
                num = (unsigned long long)(uintptr_t)va_arg(ap, void*);
#else
                num = (unsigned long)(uintptr_t)va_arg(ap, void*);
#endif
                base = 16;
                goto number;

            // (unsigned) hexadecimal
            case 'x':
                num  = getuint(ap, lflag);
                base = 16;
            number:
                if (printnum(_fputch, f, putdat, num, base, width, padc) == -1)
                    return;
                break;

            // escape character
            case '^':
                if ((*_fputch)(f, 0x1b, putdat) == -1)
                    return;
                break;

            // escaped '%' character
            case '%':
                (*_fputch)(f, ch, putdat);
                break;

            // unrecognized escape sequence - just print it literally
            default:
                (*_fputch)(f, '%', putdat);
                for (fmt--; fmt[-1] != '%'; fmt--)
                    /* do nothing */;
                break;
        }
    }
}

void fprintfmt(int (*_fputch)(void*, int, void*), void* f, void* putdat, const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintfmt(_fputch, f, putdat, fmt, ap);
    va_end(ap);
}

struct sprintbuf {
    size_t cnt;
    size_t max;
    char* buf;
};

static int sprintputch(void* f, int ch, struct sprintbuf* b) {
    __UNUSED(f);

    if (b->cnt >= b->max)
        return -1;

    b->buf[b->cnt++] = ch;
    return 0;
}

int vsnprintf(char* buf, size_t n, const char* fmt, va_list ap) {
    struct sprintbuf b = {0, n, buf};

    if (!buf || n < 1)
        return 0;

    // print the string to the buffer
    vfprintfmt((void*)sprintputch, (void*)0, &b, fmt, ap);

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
