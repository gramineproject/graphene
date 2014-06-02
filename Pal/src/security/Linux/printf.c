// Implementation of cprintf console output for user environments,
// based on printfmt() and the sys_cputs() system call.
//
// cprintf is a debugging statement, not a generic output statement.
// It is very important that it always go to the console, especially when 
// debugging file descriptor code!

#include <linux/unistd.h>
#include "utils.h"

// Collect up to PRINTBUF_SIZE characters into a buffer
// and perform ONE system call to print all of them,
// in order to make the lines output to the console atomic
// and prevent interrupts from causing context switches
// in the middle of a console output line and such.

#define PRINTBUF_SIZE 64

struct printbuf {
	int idx;	// current buffer index
	int cnt;	// total bytes printed so far
	char buf[PRINTBUF_SIZE];
};

struct sprintbuf {
	char *buf;
	char *ebuf;
	int cnt;
};

#define sys_cputs(fd, bf, cnt) INLINE_SYSCALL(write, 3, (fd), (bf), (cnt))

static void
fputch(int fd, int ch, struct printbuf *b)
{
	b->buf[b->idx++] = ch;
	if (b->idx == PRINTBUF_SIZE-1) {
		sys_cputs(fd, b->buf, b->idx);
		b->idx = 0;
	}
	b->cnt++;
}

static int
vprintf(const char *fmt, va_list ap)
{
	struct printbuf b;

	b.idx = 0;
	b.cnt = 0;
	vfprintfmt((void *) &fputch, (void *) 1, &b, fmt, ap);
	sys_cputs(1, b.buf, b.idx);

	return b.cnt;
}

int
printf(const char *fmt, ...)
{
	va_list ap;
	int cnt;

	va_start(ap, fmt);
	cnt = vprintf(fmt, ap);
	va_end(ap);

	return cnt;
}

static void
sprintputch(int fd, int ch, struct sprintbuf * b)
{
	b->cnt++;
	if (b->buf < b->ebuf)
		*b->buf++ = ch;
}

int
vsprintf(char * buf, int n, const char * fmt, va_list ap)
{
	struct sprintbuf b = {buf, buf + n - 1, 0};

	if (buf == NULL || n < 1) {
		return -1;
	}

	// print the string to the buffer
	vfprintfmt((void *) sprintputch, (void *) 0, &b, fmt, ap);

	// null terminate the buffer
	*b.buf = '\0';

	return b.cnt;
}

int
snprintf(char * buf, size_t n, const char * fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vsprintf(buf, n, fmt, ap);
	va_end(ap);

	return rc;
}
