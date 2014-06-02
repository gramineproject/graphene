#include <stdio.h>
#include <stdlib.h>

extern	int	get_enough(int);

int
main()
{
	putenv("LOOP_O=0.0");
	putenv("TIMING_O=0.0");
	printf("%u\n", get_enough(0));
	return (0);
}
