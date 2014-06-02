/*
 * mhz.c - calculate clock rate and megahertz
 *
 * Usage: mhz [-c]
 *
 *******************************************************************
 *
 * Caveat emptor and other warnings
 *
 * This code must be compiled using the optimizer!  If you don't
 * compile this using the optimizer, then many compilers don't
 * make good use of the registers and your inner loops end up
 * using stack variables, which is SLOW.  
 *
 * Also, it is sensitive to other processor load.  When running
 * mhz with "rtprio" (real-time priority), I have never had mhz
 * make a mistake on my machine.  At other times mhz has been
 * wrong about 10% of the time.
 *
 * If there is too much noise/error in the data, then this program
 * will usually return a clock speed that is too high.
 *
 *******************************************************************
 * 
 * Constraints
 *
 * mhz.c is meant to be platform independent ANSI/C code, and it 
 * has as little platform dependent code as possible.  
 *
 * This version of mhz is designed to eliminate the variable 
 * instruction counts used by different compilers on different 
 * architectures and instruction sets.  It is also structured to
 * be tightly interlocked so processors with super-scalar elements
 * or dynamic instructure reorder buffers cannot overlap the
 * execution of the expressions.
 *
 * We have to try and make sure that the code in the various
 * inner loops does not fall out of the on-chip instruction cache
 * and that the inner loop variables fit inside the register set.
 * The i386 only has six addressable registers, so we had to make
 * sure that the inner loop procedures had fewer variables so they
 * would not spill onto the stack.
 *
 *******************************************************************
 *
 * Algorithm
 *
 * We can compute the CPU cycle time if we can get the compiler
 * to generate (at least) two instruction sequences inside loops
 * where the inner loop instruction counts are relatively prime.  
 * We have several different loops to increase the chance that 
 * two of them will be relatively prime on any given architecture.  
 *
 * This technique makes no assumptions about the cost of any single
 * instruction or the number of instructions used to implement a
 * given expression.  We just hope that the compiler gets at least
 * two inner loop instruction sequences with lengths that are
 * relatively prime.  The "relatively prime" makes the greatest
 * common divisor method work.  If all the instructions sequences
 * have a common factor (e.g. 2), then the apparent CPU speed will
 * be off by that common factor.  Also, if there is too much
 * variability in the data so there is no apparent least common
 * multiple within the error bounds set in multiple_approx, then
 * we simply return the maximum clock rate found in the loops.
 *
 * The processor's clock speed is the greatest common divisor
 * of the execution frequencies of the various loops.  For
 * example, suppose we are trying to compute the clock speed
 * for a 120Mhz processor, and we have two loops:
 *	SHR		--- two cycles to shift right
 *	SHR;ADD		--- three cycles to SHR and add
 * then the expression duration will be:
 *	SHR		11.1ns (2 cycles/SHR)
 *	SHR;ADD		16.6ns (3 cycles/SHR;ADD)
 * so the greatest common divisor is 5.55ns and the clock speed
 * is 120Mhz.  Aside from extraneous variability added by poor 
 * benchmarking hygiene, this method should always work when we 
 * are able to get loops with cycle counts that are relatively 
 * prime.
 *
 * Suppose we are unlucky, and we have our two loops do
 * not have relatively prime instruction counts.  Suppose
 * our two loops are:
 *	SHR		11.1ns (2 cycles/SHR)
 *	SHR;ADD;SUB	22.2ns (4 cycles/SHR;ADD;SUB)
 * then the greatest common divisor will be 11.1ns, so the clock
 * speed will appear to be 60Mhz.
 *
 * The loops provided so far should have at least two relatively 
 * prime loops on nearly all architectures.
 *
 *******************************************************************
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Silicon Graphics is gratefully acknowledged.
 * Support for this development by Hewlett Packard is gratefully acknowledged.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 *
 *******************************************************************
 */
char	*id = "$Id$\n";

#include "bench.h"
#include <math.h>

typedef	long	TYPE;

#define TEN(A)		A A A A A A A A A A
#define HUNDRED(A)	TEN(A) TEN(A) TEN(A) TEN(A) TEN(A) \
			TEN(A) TEN(A) TEN(A) TEN(A) TEN(A)

#define MHZ(M, contents)						\
char*									\
name_##M()								\
{									\
	return #contents;						\
}									\
									\
TYPE**									\
_mhz_##M (register long n, register TYPE **p, 				\
	  register TYPE a, register TYPE b)				\
{ 									\
	for (; n > 0; --n) {						\
		HUNDRED(contents)					\
	}								\
	return p + a + b;						\
}									\
									\
void									\
mhz_##M(int enough)							\
{									\
	TYPE	__i = 1;						\
	TYPE	*__x=(TYPE *)&__x, **__p=(TYPE **)__x, **__q = NULL;	\
	_mhz_##M(1, __p, 1, 1);						\
	BENCH1(__q = _mhz_##M(__n, __p, __i, __i); __n = 1;, enough)	\
	use_pointer((void*)__q);					\
	save_n(100 * get_n()); /* # of expressions executed */		\
}

MHZ(1, p=(TYPE**)*p;)
MHZ(2, a^=a+a;)
MHZ(3, a^=a+a+a;)
MHZ(4, a>>=b;)
MHZ(5, a>>=a+a;)
MHZ(6, a^=a<<b;)
MHZ(7, a^=a+b;)
MHZ(8, a+=(a+b)&07;)
MHZ(9, a++;a^=1;a<<=1;)

typedef void (*loop_f)(int);
loop_f loops[] = {
	mhz_1,
	mhz_2,
	mhz_3,
	mhz_4,
	mhz_5,
	mhz_6,
	mhz_7,
	mhz_8,
	mhz_9,
};


#define NTESTS	(sizeof(loops) / sizeof(loop_f))
#define BIT_SET(A,bit) ((A) & 1 << (bit))


/*
 * This is used to filter out bad points (mostly ones that have had
 * their inner loop optimized away).  Bad points are those with values
 * less than 1/20th of the median value and more than 20 times the
 * median value.
 *
 * filter_data returns the number of valid data points, and puts the
 * valid points in the lower part of the values[] array.
 */
int
filter_data(double values[], int size)
{
	int i;
	int tests;
	double median;
	double *d = (double *)malloc(size * sizeof(double));

	for (i = 0; i < size; ++i) d[i] = values[i];
	qsort(d, size, sizeof(double), double_compare);

	median = d[size/2];
	if (size > 0 && size % 2 == 0) median = (median + d[size/2 - 1]) / 2.0;

	free(d);

	/* if the data point is inside the envelope of acceptable 
	 * results, then keep it, otherwise discard it
	 */
	for (i = 0, tests = 0; i < size; ++i)
		if (0.05 * median < values[i] && values[i] < 20.0 * median) {
			if (i > tests) values[tests] = values[i];
			tests++;
		}

	return tests;
}

/*
 * make sure that there are enough points with significantly
 * different data values (greater than 5% difference) in the
 * data subset.
 */
int
classes(double values[], int size)
{
	int i;
	double median;
	double *d = (double *)malloc(size * sizeof(double));
	int classid;

	for (i = 0; i < size; ++i) d[i] = values[i];
	qsort(d, size, sizeof(double), double_compare);

	median = d[size/2];
	if (size % 2 == 0) median = (median + d[size/2 - 1]) / 2.0;

	/* if the difference is less than 1/20th of the median, then
	 * we assume that the two points are the same
	 */
	for (i = 1, classid = 1; i < size; ++i)
	    if ((d[i] - d[i-1]) > 0.05 * median) classid++;

	free(d);
	return classid;
}

/*
 * mode
 *
 * return the most common value (within 1MHz)
 */
int
mode(double values[], int n)
{
	int	i, n_mode, n_curr;
	int	mode, curr;

	qsort(values, n, sizeof(double), double_compare);

	n_mode = 1;
	n_curr = 1;
	mode = (int)(values[0] + 0.5);
	curr = (int)(values[0] + 0.5);

	for (i = 1; i < n; ++i) {
		int v = (int)(values[i] + 0.5);
		if (curr != v) {
			curr = v;
			n_curr = 0;
		}
		n_curr++;
		if (n_curr > n_mode) {
			mode = curr;
			n_mode = n_curr;
		}
	}

	return mode;
}

/*
 * cross_values
 *
 * This routine will create new data points by subtracting pairs
 * of data points.
 */
void
cross_values(double values[], int size, double **cvalues, int *csize)
{
	int	i, j;

	*cvalues = (double *)malloc(size * size * sizeof(double));
	*csize = 0;

	for (i = 0; i < size; ++i) {
		(*cvalues)[(*csize)++] = values[i];
		/* create new points with the differences */
		for (j = i + 1; j < size; ++j) {
			(*cvalues)[(*csize)++] = ABS(values[i] - values[j]);
		}
	}
}


/*
 * gcd
 *
 * return the greatest common divisor of the passed values (within a
 * margin of error because these are experimental results, not
 * theoretical numbers).  We do this by guessing how many instructions
 * are in each loop, and then trying to fit a straight line through
 * the (instruction count, time) points.  The regression is of the
 * form:
 *
 *	y = a + b * x
 *
 * The time for an individual instruction is "b", while "a" should
 * be 0.  The trick is to figure out which guess is the right one!
 *
 * We assume that the gcd is the first value at which we have 
 * significantly improved regression fit (as measured by chi2).
 *
 * We increase the number of experimental points (and generate
 * more small points) by adding points for the differences between
 * measured values (and compute the standard error appropriately).
 *
 * We want the regression line to go through the origin, so we
 * add an artificial point at (0,0) with a tiny standard error.
 */
double 
gcd(double values[], int size)
{
/* assumption: shortest inner loop has no more than this many instructions */
#define	MAX_COUNT	6
	int	i, n, count;
	double	min, result, min_chi2 = 0.0, a, b, sig_a, sig_b, chi2;
	double *y, *x = (double *)malloc(size * size * sizeof(double));

	/* find the smallest value */
	result = min = double_min(values, size);

	/* create new points by subtracting each pair of values */
	cross_values(values, size, &y, &n);

	/* make sure the regression goes through the origin */
	y[n++] = 0.0;

	for (count = 1; count < MAX_COUNT; ++count) {
		/* 
		 * given the minimum loop has "count" instructions,
		 * guess how many instructions each other loop contains
		 */
		for (i = 0; i < n; ++i) {
			int m = (int)((double)count * y[i] / min + 0.5);
			x[i] = (double)m;
		}

		/* find the regression of the samples */
		regression(x, y, NULL, n, &a, &b, &sig_a, &sig_b, &chi2);

		if (count == 1 || count * count * chi2 < min_chi2) {
			result = b;
			min_chi2 = chi2;
		}
	}
	free(x);
	free(y);
	return result;
}

/*
 * compute the gcd of many possible combinations of experimental values
 * and return the mode of the results to reduce the impact
 * of a few bad experimental measurements on the computed result.
 *
 * r	- pointer to the array of experimental results
 * off	- offset of the result we want.  TRIES-1 == minimum result.
 */
int
compute_mhz(result_t *r)
{
	int	i, j, mhz[2], n, subset, ntests;
	double	data[NTESTS], results[1<<NTESTS];

	for (i = 0; i < 2; ++i) {
		for (subset = 0, ntests = 0; subset < (1<<NTESTS); ++subset) {
			for (j = 0, n = 0; j < NTESTS; ++j)
				if (BIT_SET(subset, j) && r[j].N > TRIES/2)
					data[n++] = r[j].u[r[j].N-1-i] / (double)r[j].n[r[j].N-1-i];
			if (n < 2
			    || (n = filter_data(data, n)) < 2
			    || classes(data, n) < 2) 
				continue;
			results[ntests++] = 1.0 / gcd(data, n);
		}
		mhz[i] = mode(results, ntests);
	}
	/* if the results agree within 1% or 1MHz, accept them */
	if (ABS(mhz[0] - mhz[1]) / (double)mhz[0] <= 0.01 
	    || ABS(mhz[0] - mhz[1]) <= 1)
		return mhz[0];

	return -1;
}

void
save_data(result_t* data, result_t* data_save)
{
	int	i;

	for (i = 0; i < NTESTS; ++i) {
		data_save[i] = data[i];
	}
}

void
print_data(double mhz, result_t* data)
{
	int	i, j;
	char	*CPU_name = "CPU";
	char	*uname = "uname";
	char	*email = "email";
	int	speed = -1;
	char	*names[NTESTS];

	names[0] = name_1();
	names[1] = name_2();
	names[2] = name_3();
	names[3] = name_4();
	names[4] = name_5();
	names[5] = name_6();
	names[6] = name_7();
	names[7] = name_8();
	names[8] = name_9();

	printf("/* \"%s\", \"%s\", \"%s\", %d, %.0f, %d, %f, %f */\n", 
	       CPU_name, uname, email, speed, 
	       mhz, get_enough(0), l_overhead(), t_overhead());
	printf("result_t* data[] = { \n");
	for (i = 0; i < NTESTS; ++i) {
	    printf("\t/* %s */ { %d, {", names[i], data[i].N);
	    for (j = 0; j < data[i].N; ++j) {
		printf("\n\t\t{ /* %f */ %lu, %lu}", data[i].u[j] / (100. * data[i].n[j]), (unsigned long)data[i].u[j], (unsigned long)data[i].n[j]);
		if (j < TRIES - 1) printf(", ");
	    }
	    if (i < NTESTS - 1) printf("}},\n");
	    else printf("}}\n");
	}
	printf("};\n");
}

int
main(int ac, char **av)
{
	int	i, j, k, mhz = -1;
	double	runtime;
	result_t data[NTESTS];
	result_t data_save[NTESTS];

	putenv("LOOP_O=0.0"); /* should be at most 1% */

	runtime = (NTESTS * TRIES * 3 * get_enough(0)) / 1000000.;
	if (runtime > 3.) {
	  fprintf(stderr, "mhz: should take approximately %.0f seconds\n", runtime);
	}

	/* make three efforts to get reliable data */
	for (i = 0; i < 3 && mhz < 0; ++i) {
	    /* initialize the data arrays */
	    for (j = 0; j < NTESTS; ++j)
		insertinit(&data[j]);

	    /*
	     * collect the data; try to minimize impact of activity bursts
	     * by putting NTESTS in the inner loop so a burst will affect
	     * one data point for all expressions first, rather than all
	     * data points for one expression.
	     */
	    for (j = 0; j < TRIES; ++j) {
		for (k = 0; k < NTESTS; ++k) {
		    (*loops[k])(0);
		    insertsort(gettime(), get_n(), &data[k]);
		}
	    }
	    save_data(data, data_save);
	    mhz = compute_mhz(data);
	}

	if (ac > 1 && !strcmp(av[1], "-d")) {
		if (ac > 1) {
			ac --;
			for (i = 1; i < ac; ++i) {
				av[i] = av[i+1];
			}
		}
		print_data(mhz, data_save);
	}

	if (mhz < 0.) {
		printf("-1 System too busy\n");
		exit(1);
	}

	if (ac == 2 && !strcmp(av[1], "-c")) {
		printf("%.4f\n", 1000. / (double)mhz);
	} else {
		printf("%d MHz, %.2f nanosec clock\n", 
		       mhz, 1000. / (double)mhz);
	}
	exit(0);
}
