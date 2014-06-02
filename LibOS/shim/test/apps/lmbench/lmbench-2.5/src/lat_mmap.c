/*
 * lat_mmap.c - time how fast a mapping can be made and broken down
 *
 * Usage: mmap size file
 *
 * XXX - If an implementation did lazy address space mapping, this test
 * will make that system look very good.  I haven't heard of such a system.
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

#define	PSIZE	(16<<10)
#define	N	10
#define	STRIDE	(10*PSIZE)
#define	MINSIZE	(STRIDE*2)

#define	CHK(x)	if ((x) == -1) { perror("x"); exit(1); }

/*
 * This alg due to Linus.  The goal is to have both sparse and full
 * mappings reported.
 */
void
mapit(int fd, size_t size, int random)
{
	char	*p, *where, *end;
	char	c = size & 0xff;

#ifdef	MAP_FILE
	where = mmap(0, size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0);
#else
	where = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
#endif
	if ((int)where == -1) {
		perror("mmap");
		exit(1);
	}
	if (random) {
		end = where + size;
		for (p = where; p < end; p += STRIDE) {
			*p = c;
		}
	} else {
		end = where + (size / N);
		for (p = where; p < end; p += PSIZE) {
			*p = c;
		}
	}
	munmap(where, size);
}

int
main(int ac, char **av)
{
	int	fd;
	size_t	size;
	int	random = 0;
	char	*prog = av[0];

	if (ac != 3 && ac != 4) {
		fprintf(stderr, "usage: %s [-r] size file\n", prog);
		exit(1);
	}
	if (strcmp("-r", av[1]) == 0) {
		random = 1;
		ac--, av++;
	}
	size = bytes(av[1]);
	if (size < MINSIZE) {	
		return (1);
	}
	CHK(fd = open(av[2], O_CREAT|O_RDWR, 0666));
	CHK(ftruncate(fd, size));
	BENCH(mapit(fd, size, random), 0);
	micromb(size, get_n());
	return(0);
}
