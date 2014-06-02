/*
 * memsize.c - figure out how much memory we have to use.
 *
 * Usage: memsize [max_wanted_in_MB]
 *
 * Copyright (c) 1995 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include "bench.h"

#define	CHK(x)	if ((x) == -1) { perror("x"); exit(1); }

#ifndef	TOO_LONG
#define	TOO_LONG	10	/* usecs */
#endif

int	alarm_triggered = 0;

void	timeit(char *where, size_t size);
static	void touchRange(char *p, size_t range, ssize_t stride);
int	test_malloc(size_t size);
void	set_alarm(uint64 usecs);
void	clear_alarm();

int
main(int ac, char **av)
{
	char	*where;
	char	*tmp;
	size_t	size = 0;
	size_t	max = 0;
	size_t	delta;

	if (ac == 2) {
		max = size = bytes(av[1]) * 1024 * 1024;
	}
	if (max < 1024 * 1024) {
		max = size = 1024 * 1024 * 1024;
	}
	/*
	 * Binary search down and then binary search up
	 */
	for (where = 0; !test_malloc(size); size >>= 1) {
		max = size;
	}
	/* delta = size / (2 * 1024 * 1024) */
	for (delta = (size >> 21); delta > 0; delta >>= 1) {
		uint64 sz = (uint64)size + (uint64)delta * 1024 * 1024;
		if (max < sz) continue;
		if (test_malloc(sz)) size = sz;
	}
	if (where = malloc(size)) {
		timeit(where, size);
		free(where);
	}
	exit (0);
}

void
timeit(char *where, size_t size)
{
	int	sum = 0;
	char	*end = where + size;
	size_t	n;
	size_t	s;
	size_t	range;
	size_t	incr = 1024 * 1024;
	ssize_t	stride;
	size_t	pagesize = getpagesize();

	if (size < 1024*1024 - 16*1024) {
		fprintf(stderr, "Bad size\n");
		return;
	}

	range = 1024 * 1024;
	incr = 1024 * 1024;
	touchRange(where, range, pagesize);
	for (range += incr; range <= size; range += incr) {
		n = range / pagesize;
		set_alarm(n * TOO_LONG);
		touchRange(where + range - incr, incr, pagesize);
		clear_alarm();
		set_alarm(n * TOO_LONG);
		start(0);
		touchRange(where, range, pagesize);
		sum = stop(0, 0);
		clear_alarm();
		if ((sum / n) > TOO_LONG || alarm_triggered) {
			size = range - incr;
			break;
		}
		for (s = 8 * 1024 * 1024; s <= range; s *= 2)
			;
		incr = s / 8;
		if (range < size && size < range + incr) {
			incr = size - range;
		}
		fprintf(stderr, "%dMB OK\r", range/(1024*1024));
	}
	fprintf(stderr, "\n");
	printf("%d\n", (size>>20));
}

static void
touchRange(char *p, size_t range, ssize_t stride)
{
	register char	*tmp = p + (stride > 0 ? 0 : range - 1);
	register size_t delta = (stride > 0 ? stride : -stride);

	while (range > delta - 1 && !alarm_triggered) {
		*tmp = 0;
		tmp += stride;
		range -= delta;
	}
}

int
test_malloc(size_t size)
{
	int	fid[2];
	int	result;
	int	status;
	void*	p;

	if (pipe(fid) < 0) {
		void* p = malloc(size);
		if (!p) return 0;
		free(p);
		return 1;
	}
	if (fork() == 0) {
		close(fid[0]);
		p = malloc(size);
		result = (p ? 1 : 0);
		write(fid[1], &result, sizeof(int));
		close(fid[1]);
		if (p) free(p);
		exit(0);
	}
	close(fid[1]);
	if (read(fid[0], &result, sizeof(int)) != sizeof(int))
		result = 0;
	close(fid[0]);
	wait(&status);
	return result;
}

void
gotalarm()
{
	alarm_triggered = 1;
}

void
set_alarm(uint64 usecs)
{
	struct itimerval value;
	struct sigaction sa;

	alarm_triggered = 0;

	sa.sa_handler = gotalarm;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, 0);

	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 0;
	value.it_value.tv_sec = usecs / 1000000;
	value.it_value.tv_usec = usecs % 1000000;

	setitimer(ITIMER_REAL, &value, NULL);
}

void
clear_alarm()
{
	struct itimerval value;

	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 0;
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &value, NULL);
}

