/*
 * clock.c
 *
 * calculate the minimum timing loop length that gives us significant results
 */
#include "bench.h"
#include "version.h"

char	*id = "$Id$";
char	*revision = "$Revision$";

main()
{
	uint64	enough;
	double	timing, loop;

	enough = get_enough(0);
	printf("ENOUGH=%lu\n", (unsigned long)enough); fflush(stdout);
	timing = t_overhead();
	printf("TIMING_OVERHEAD=%f\n", timing); fflush(stdout);
	loop = l_overhead();
	printf("LOOP_OVERHEAD=%f\n", loop);
	printf("# version %d.%d\n", MAJOR, MINOR);
	exit(0);
}
