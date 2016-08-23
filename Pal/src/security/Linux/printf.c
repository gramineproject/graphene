// Implementation of cprintf console output for user environments,
// based on printfmt() and the sys_cputs() system call.
//
// cprintf is a debugging statement, not a generic output statement.
// It is very important that it always go to the console, especially when 
// debugging file descriptor code!

#include <linux/unistd.h>
#include "internal.h"

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

static int
fputch(int fd, int ch, struct printbuf *b)
{
	b->buf[b->idx++] = ch;
	if (b->idx == PRINTBUF_SIZE - 1) {
		sys_cputs(fd, b->buf, b->idx);
		b->idx = 0;
	}
	b->cnt++;
	return 0;
}

static int
vprintf(const char *fmt, va_list *ap)
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
	cnt = vprintf(fmt, &ap);
	va_end(ap);

	return cnt;
}
