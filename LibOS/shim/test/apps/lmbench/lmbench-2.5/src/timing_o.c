#include <stdio.h>
#include "bench.h"

int
main()
{
	putenv("LOOP_O=0.0");
	printf("%lu\n", (unsigned long)t_overhead());
	return (0);
}
