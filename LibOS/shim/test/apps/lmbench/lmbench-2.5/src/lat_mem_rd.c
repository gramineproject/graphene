/*
 * lat_mem_rd.c - measure memory load latency
 *
 * usage: lat_mem_rd size-in-MB stride [stride ...]
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"
#define N       1000000	/* Don't change this */
#define STRIDE  (512/sizeof(char *))
#define	MEMTRIES	4
#define	LOWER	512
void	loads(char *addr, size_t range, size_t stride);
size_t	step(size_t k);

int
main(int ac, char **av)
{
	size_t	len;
	size_t	range;
	size_t	stride;
	int	i;
        char   *addr;

        len = atoi(av[1]) * 1024 * 1024;
        addr = (char *)malloc(len);

	if (av[2] == 0) {
		fprintf(stderr, "\"stride=%d\n", STRIDE);
		for (range = LOWER; range <= len; range = step(range)) {
			loads(addr, range, STRIDE);
		}
	} else {
		for (i = 2; i < ac; ++i) {
			stride = bytes(av[i]);
			fprintf(stderr, "\"stride=%d\n", stride);
			for (range = LOWER; range <= len; range = step(range)) {
				loads(addr, range, stride);
			}
			fprintf(stderr, "\n");
		}
	}
	return(0);
}

void
loads(char *addr, size_t range, size_t stride)
{
	register char **p = 0 /* lint */;
	size_t	i;
	int	tries = 0;
	int	result = 0x7fffffff;
	double	time;

     	if (stride & (sizeof(char *) - 1)) {
		printf("lat_mem_rd: stride must be aligned.\n");
		return;
	}
	
	if (range < stride) {
		return;
	}

	/*
	 * First create a list of pointers.
	 *
	 * This used to go forwards, we want to go backwards to try and defeat
	 * HP's fetch ahead.
	 *
	 * We really need to do a random pattern once we are doing one hit per 
	 * page.
	 */
	for (i = stride; i < range; i += stride) {
		*(char **)&addr[i] = (char*)&addr[i - stride];
	}
	*(char **)&addr[0] = (char*)&addr[i - stride];
	p = (char**)&addr[0];

	/*
	 * Now walk them and time it.
	 */
        for (tries = 0; tries < MEMTRIES; ++tries) {
                /* time loop with loads */
#define	ONE	p = (char **)*p;
#define	FIVE	ONE ONE ONE ONE ONE
#define	TEN	FIVE FIVE
#define	FIFTY	TEN TEN TEN TEN TEN
#define	HUNDRED	FIFTY FIFTY
		i = N;
                start(0);
                while (i >= 1000) {
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			HUNDRED
			i -= 1000;
                }
		i = stop(0,0);
		use_pointer((void *)p);
		if (i < result) {
			result = i;
		}
	}
	/*
	 * We want to get to nanoseconds / load.  We don't want to
	 * lose any precision in the process.  What we have is the
	 * milliseconds it took to do N loads, where N is 1 million,
	 * and we expect that each load took between 10 and 2000
	 * nanoseconds.
	 *
	 * We want just the memory latency time, not including the
	 * time to execute the load instruction.  We allow one clock
	 * for the instruction itself.  So we need to subtract off
	 * N * clk nanoseconds.
	 *
	 * lmbench 2.0 - do the subtration later, in the summary.
	 * Doing it here was problematic.
	 *
	 * XXX - we do not account for loop overhead here.
	 */
	time = (double)result;
	time *= 1000.;				/* convert to nanoseconds */
	time /= (double)N;			/* nanosecs per load */
	fprintf(stderr, "%.5f %.3f\n", range / (1024. * 1024), time);
}

size_t
step(size_t k)
{
	if (k < 1024) {
		k = k * 2;
        } else if (k < 4*1024) {
		k += 1024;
	} else {
		size_t s;

		for (s = 32 * 1024; s <= k; s *= 2)
			;
		k += s / 16;
	}
	return (k);
}
