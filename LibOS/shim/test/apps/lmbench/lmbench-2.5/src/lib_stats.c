#include <math.h>
#include "bench.h"

#define BOOTSTRAP_COUNT	200

/*
 * a comparison function used by qsort
 */
int
int_compare(const void *a, const void *b)
{
	if (*(int*)a < *(int*)b) return -1;
	if (*(int*)a > *(int*)b) return 1;
	return 0;
}

/*
 * a comparison function used by qsort
 */
int
uint64_compare(const void *a, const void *b)
{
	if (*(uint64*)a < *(uint64*)b) return -1;
	if (*(uint64*)a > *(uint64*)b) return  1;
	return 0;
}

/*
 * a comparison function used by qsort
 */
int
double_compare(const void *a, const void *b)
{
	if (*(double*)a < *(double*)b) return -1;
	if (*(double*)a > *(double*)b) return 1;
	return 0;
}

/*
 * return the median value of an array of int
 */
int
int_median(int *values, int size)
{
	qsort(values, size, sizeof(int), int_compare);

	if (size == 0) return 0;

	if (size % 2) {
	    return values[size/2];
	}
	return (values[size/2 - 1] + values[size/2]) / 2;
}

/*
 * return the median value of an array of int
 */
uint64
uint64_median(uint64 *values, int size)
{
	qsort(values, size, sizeof(uint64), uint64_compare);

	if (size == 0) return 0;

	if (size % 2) {
	    return values[size/2];
	}
	return (values[size/2 - 1] + values[size/2]) / 2;
}

/*
 * return the median value of an array of doubles
 */
double
double_median(double *values, int size)
{
	qsort(values, size, sizeof(double), double_compare);

	if (size == 0) return 0.;

	if (size % 2) {
	    return values[size/2];
	}
	return (values[size/2 - 1] + values[size/2]) / 2.0;
}

/*
 * return the mean value of an array of int
 */
int
int_mean(int *values, int size)
{
	int	i;
	int	sum = 0;
	for (i = 0; i < size; ++i)
		sum += values[i];
	return sum / size;
}

/*
 * return the mean value of an array of int
 */
uint64
uint64_mean(uint64 *values, int size)
{
	int	i;
	uint64	sum = 0;
	for (i = 0; i < size; ++i)
		sum += values[i];
	return sum / size;
}

/*
 * return the mean value of an array of doubles
 */
double
double_mean(double *values, int size)
{
	int	i;
	double	sum = 0.0;
	for (i = 0; i < size; ++i)
		sum += values[i];
	return sum / (double)size;
}

/*
 * return the min value of an array of int
 */
int
int_min(int *values, int size)
{
	int	i;
	int	min = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] < min) min = values[i];
	return min;
}

/*
 * return the min value of an array of int
 */
uint64
uint64_min(uint64 *values, int size)
{
	int	i;
	uint64	min = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] < min) min = values[i];
	return min;
}

/*
 * return the min value of an array of doubles
 */
double
double_min(double *values, int size)
{
	int	i;
	double	min = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] < min) min = values[i];
	return min;
}

/*
 * return the max value of an array of int
 */
int
int_max(int *values, int size)
{
	int	i;
	int	max = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] > max) max = values[i];
	return max;
}

/*
 * return the max value of an array of int
 */
uint64
uint64_max(uint64 *values, int size)
{
	int	i;
	uint64	max = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] > max) max = values[i];
	return max;
}

/*
 * return the max value of an array of doubles
 */
double
double_max(double *values, int size)
{
	int	i;
	double	max = values[0];
	for (i = 1; i < size; ++i)
		if (values[i] > max) max = values[i];
	return max;
}

/*
 * return the standard error of an array of ints
 */
double	int_stderr(int *values, int size)
{
	int	i;
	double	sum = 0.0;
	int	mean = int_mean(values, size);

	for (i = 0; i < size; ++i)
		sum += (double)((values[i] - mean) * (values[i] - mean));
	sum /= (double)(size * size);

	return sqrt(sum);
}

/*
 * return the standard error of an array of uint64s
 */
double	uint64_stderr(uint64 *values, int size)
{
	int	i;
	double	sum = 0.0;
	uint64	mean = uint64_mean(values, size);

	for (i = 0; i < size; ++i)
		sum += (double)((values[i] - mean) * (values[i] - mean));
	sum /= (double)(size * size);

	return sqrt(sum);
}

/*
 * return the standard error of an array of doubles
 */
double	double_stderr(double *values, int size)
{
	int	i;
	double	sum = 0.0;
	double	mean = double_mean(values, size);

	for (i = 0; i < size; ++i)
		sum += (double)((values[i] - mean) * (values[i] - mean));
	sum /= (double)(size * size);

	return sqrt(sum);
}

/*
 * BOOTSTRAP:
 *
 * stderr = sqrt(sum_i(s[i] - sum_j(s[j])/B)**2 / (B - 1))
 *
 * Reference: "An Introduction to the Bootstrap" by Bradley
 *	Efron and Robert J. Tibshirani, page 12.
 */

/*
 * return the bootstrap estimation of the standard error 
 * of an array of ints
 */
double	int_bootstrap_stderr(int *values, int size, int_stat f)
{
	int	i, j;
	int    *samples = (int*)malloc(size * sizeof(int));
	double *s = (double*)malloc(BOOTSTRAP_COUNT * sizeof(double));
	double	s_sum = 0;
	double	sum = 0;

	/* generate the stderr for each of the bootstrap samples */
	for (i = 0; i < BOOTSTRAP_COUNT; ++i) {
		for (j = 0; j < size; ++j)
			samples[j] = values[rand() % size];
		s[i] = (double)(*f)(samples, size);
		s_sum += s[i];	/* CHS: worry about overflow */
	}
	s_sum /= (double)BOOTSTRAP_COUNT;
	
	for (i = 0; i < BOOTSTRAP_COUNT; ++i) 
		sum += (s[i] - s_sum) * (s[i] - s_sum);

	sum /= (double)(BOOTSTRAP_COUNT - 1);

	free(samples);
	free(s);

	return sqrt(sum);
}

/*
 * return the bootstrap estimation of the standard error 
 * of an array of uint64s
 */
double	uint64_bootstrap_stderr(uint64 *values, int size, uint64_stat f)
{
	int	i, j;
	uint64 *samples = (uint64*)malloc(size * sizeof(uint64));
	double *s = (double*)malloc(BOOTSTRAP_COUNT * sizeof(double));
	double	s_sum;
	double	sum;

	/* generate the stderr for each of the bootstrap samples */
	for (i = 0, s_sum = 0.0; i < BOOTSTRAP_COUNT; ++i) {
		for (j = 0; j < size; ++j) 
			samples[j] = values[rand() % size];
		s[i] = (double)(*f)(samples, size);
		s_sum += s[i];	/* CHS: worry about overflow */
	}
	s_sum /= (double)BOOTSTRAP_COUNT;
	
	for (i = 0, sum = 0.0; i < BOOTSTRAP_COUNT; ++i) 
		sum += (s[i] - s_sum) * (s[i] - s_sum);

	free(samples);
	free(s);

	return sqrt(sum/(double)(BOOTSTRAP_COUNT - 1));
}

/*
 * return the bootstrap estimation of the standard error 
 * of an array of doubles
 */
double	double_bootstrap_stderr(double *values, int size, double_stat f)
{
	int	i, j;
	double *samples = (double*)malloc(size * sizeof(double));
	double *s = (double*)malloc(BOOTSTRAP_COUNT * sizeof(double));
	double	s_sum = 0;
	double	sum = 0;

	/* generate the stderr for each of the bootstrap samples */
	for (i = 0; i < BOOTSTRAP_COUNT; ++i) {
		for (j = 0; j < size; ++j) 
			samples[j] = values[rand() % size];
		s[i] = (*f)(samples, size);
		s_sum += (double)s[i];	/* CHS: worry about overflow */
	}
	s_sum /= (double)BOOTSTRAP_COUNT;
	
	for (i = 0; i < BOOTSTRAP_COUNT; ++i) 
		sum += (s[i] - s_sum) * (s[i] - s_sum);

	sum /= (double)(BOOTSTRAP_COUNT - 1);

	free(samples);
	free(s);

	return sqrt(sum);
}

/*
 * regression(x, y, sig, n, a, b, sig_a, sig_b, chi2)
 *
 * This routine is derived from equations in "Numerical Recipes in C" 
 * (second edition) by Press, et. al.,  pages 661-665.
 *
 * compute the linear regression y = a + bx for (x,y), where y[i] has 
 * standard deviation sig[i].
 *
 * returns the coefficients a and b, along with an estimation of their
 * error (standard deviation) in sig_a and sig_b.
 *
 * returns chi2 for "goodness of fit" information.
 */

void
regression(double *x, double *y, double *sig, int n,
	   double *a, double *b, double *sig_a, double *sig_b, 
	   double *chi2)
{
	int	i;
	double	S = 0.0, Sx = 0.0, Sy = 0.0, Stt = 0.0, Sx_S;

	/* compute some basic statistics */
	for (i = 0; i < n; ++i) {
		/* Equations 15.2.4: for S, Sx, Sy */
		double	weight = 1.0 / (sig ? sig[i] * sig[i] : 1.0);
		S += weight;
		Sx += weight * x[i];
		Sy += weight * y[i];
	}

	*b = 0.0;
	Sx_S = Sx / S;
	for (i = 0; i < n; ++i) {
		/* 
		 * Equation 15.2.15 for t
		 * Equation 15.2.16 for Stt
		 * Equation 15.2.17 for b, do summation portion of equation
		 *	compute Sum i=0,n-1 (t_i * y[i] / sig[i]))
		 */
		double t_i = (x[i] - Sx_S) / (sig ? sig[i] : 1.0);
		Stt += t_i * t_i;
		*b  += t_i * y[i] / (sig ? sig[i] : 1.0);
	}

	/*
	 * Equation 15.2.17 for b, do 1/Stt * summation
	 * Equation 15.2.18 for a
	 * Equation 15.2.19 for sig_a
	 * Equation 15.2.20 for sig_b
	 */
	*b /= Stt;
	*a = (Sy - *b * Sx) / S;
	*sig_a = sqrt((1.0 + (Sx * Sx) / (S * Stt)) / S);
	*sig_b = sqrt(1.0 / Stt);

	/* Equation 15.2.2 for chi2, the merit function */
	*chi2 = 0.0;
	for (i = 0; i < n; ++i) {
		double merit = (y[i] - ((*a) + (*b) * x[i])) / (sig ? sig[i] : 1.0);
		*chi2 += merit * merit;
	}
	if (sig == NULL) {
	  *sig_a *= sqrt((*chi2) / (n - 2));
	  *sig_b *= sqrt((*chi2) / (n - 2));
	}
}

