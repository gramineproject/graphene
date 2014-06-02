#define	 _LIB /* bench.h needs this */
#include "bench.h"
#include <math.h>
#include <stdio.h>

/**
 * 95% confidence interval is [y - ci_width, y + ci_width]
 */
double ci_width(double stddev, int n)
{
	double c = 0;

	assert(n > 0);

	if (n >= 120)
		c = 1.96;
	else if (n >= 90)
		c = 1.987;
	else if (n >= 60)
		c = 2.0;
	else if (n >= 40)
		c = 2.021;
	else if (n >= 30)
		c = 2.042;
	else if (n >= 25)
		c = 2.06;
	else if (n >= 20)
		c = 2.086;
	else if (n >= 15)
		c = 2.131;
	else if (n >= 10)
		c = 2.228;
	else if (n >= 5)
		c = 2.571;
	else if (n == 4)
		c = 2.776;
	else if (n == 3)
		c = 3.182;
	else if (n == 2)
		c = 4.303;
	else if (n == 1)
		c = 12.706;
	else {
		fprintf(stderr,"ERROR: n < 1. cannot calculate confidence interval.");
		return 0;
	}

	return (c * stddev/sqrt((double)n));
}
