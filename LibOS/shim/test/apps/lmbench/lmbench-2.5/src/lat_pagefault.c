/*
 * lat_pagefault.c - time a page fault in
 *
 * Usage: lat_pagefault file [file file...]
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

#define	CHK(x)	if ((x) == -1) { perror("x"); exit(1); }

void	timeit(char *file, char *where, int size);

int
main(int ac, char **av)
{
#ifdef	MS_INVALIDATE
	int fd;
	char *where;
	struct stat sbuf;

	if (ac != 2) {
		fprintf(stderr, "usage: %s file\n", av[0]);
		exit(1);
	}
	CHK(fd = open(av[1], 0));
	CHK(fstat(fd, &sbuf));
	sbuf.st_size &= ~(16*1024 - 1);		/* align it */
	if (sbuf.st_size < 1024*1024) {
		fprintf(stderr, "%s: %s too small\n", av[0], av[2]);
		exit(1);
	}
	where = mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (msync(where, sbuf.st_size, MS_INVALIDATE) != 0) {
		perror("msync");
		exit(1);
	}
	timeit(av[1], where, sbuf.st_size);
	munmap(where, sbuf.st_size);
#endif
	return(0);
}

/*
 * Get page fault times by going backwards in a stride of 256K
 * We don't want to do this in a loop, it needs a hi res clock.
 * XXX - hires.
 */
void
timeit(char *file, char *where, int size)
{
	char	*end = where + size - 16*1024;
	int	sum = 0;
	int	n = 0, usecs = 0;

	start(0);
	while (end > where) {
		sum += *end;
		end -= 256*1024;
		n++;
	}
	usecs = stop(0,0);
	fprintf(stderr, "n=%d, usecs=%lu\n", (int)n, (unsigned long)usecs);
	use_int(sum);
	fprintf(stderr, "Pagefaults on %s: %d usecs\n", file, usecs/n);
}
