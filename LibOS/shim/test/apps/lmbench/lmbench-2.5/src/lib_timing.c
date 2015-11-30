/*
 * a timing utilities library
 *
 * Requires 64bit integers to work.
 *
 * %W% %@%
 *
 * Copyright (c) 1994-1998 Larry McVoy.
 */
#define	 _LIB /* bench.h needs this */
#include "bench.h"
#include "confidence.h"
#include <math.h>

//#define _DEBUG

#ifdef KVM_LMBENCH 
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../../kvmbenchmark/pvclock_bench.h"
#endif

#define	nz(x)	((x) == 0 ? 1 : (x))

/*
 * I know you think these should be 2^10 and 2^20, but people are quoting
 * disk sizes in powers of 10, and bandwidths are all power of ten.
 * Deal with it.
 */
#define	MB	(1000*1000.0)
#define	KB	(1000.0)

static double u_var, u_mean, ops_s_mean, ops_s_var;
static struct timeval start_tv, stop_tv, stop_mean_tv, stop_var_tv;
FILE		*ftiming;
volatile uint64	use_result_dummy;	/* !static for optimizers. */
static	uint64	iterations;
static	void	init_timing(void);

#if defined(hpux) || defined(__hpux)
#include <sys/mman.h>
#endif

#ifdef	RUSAGE
#include <sys/resource.h>
#define	SECS(tv)	(tv.tv_sec + tv.tv_usec / 1000000.0)
#define	mine(f)		(int)(ru_stop.f - ru_start.f)

static struct rusage ru_start, ru_stop;

void
rusage(void)
{
	double  sys, user, idle;
	double  per;

	sys = SECS(ru_stop.ru_stime) - SECS(ru_start.ru_stime);
	user = SECS(ru_stop.ru_utime) - SECS(ru_start.ru_utime);
	idle = timespent() - (sys + user);
	per = idle / timespent() * 100;
	if (!ftiming) ftiming = stderr;
	fprintf(ftiming, "real=%.2f sys=%.2f user=%.2f idle=%.2f stall=%.0f%% ",
	    timespent(), sys, user, idle, per);
	fprintf(ftiming, "rd=%d wr=%d min=%d maj=%d ctx=%d\n",
	    mine(ru_inblock), mine(ru_oublock),
	    mine(ru_minflt), mine(ru_majflt),
	    mine(ru_nvcsw) + mine(ru_nivcsw));
}

#endif	/* RUSAGE */
/*
 * Redirect output someplace else.
 */
void
timing(FILE *out)
{
	ftiming = out;
}

/*
 * Start timing now.
 */
void
start(struct timeval *tv)
{
	if (tv == NULL) {
		tv = &start_tv;
	}
#ifdef	RUSAGE
	getrusage(RUSAGE_SELF, &ru_start);
#endif
	(void) gettimeofday(tv, (struct timezone *) 0);
}

/*
 * Stop timing and return real time in microseconds.
 */
uint64
stop(struct timeval *begin, struct timeval *end)
{
	if (end == NULL) {
		end = &stop_tv;
	}
	(void) gettimeofday(end, (struct timezone *) 0);
#ifdef	RUSAGE
	getrusage(RUSAGE_SELF, &ru_stop);
#endif

	if (begin == NULL) {
		begin = &start_tv;
	}
	return tvdelta(begin, end);
}

uint64
now(void)
{
	struct timeval t;
	uint64	m;

	(void) gettimeofday(&t, (struct timezone *) 0);
	m = t.tv_sec;
	m *= 1000000;
	m += t.tv_usec;
	return (m);
}

double
Now(void)
{
	struct timeval t;

	(void) gettimeofday(&t, (struct timezone *) 0);
	return (t.tv_sec * 1000000.0 + t.tv_usec);
}

uint64
delta(void)
{
	static struct timeval last;
	struct timeval t;
	struct timeval diff;
	uint64	m;

	(void) gettimeofday(&t, (struct timezone *) 0);
	if (last.tv_usec) {
		tvsub(&diff, &t, &last);
		last = t;
		m = diff.tv_sec;
		m *= 1000000;
		m += diff.tv_usec;
		return (m);
	} else {
		last = t;
		return (0);
	}
}

double
Delta(void)
{
	struct timeval t;
	struct timeval diff;

	(void) gettimeofday(&t, (struct timezone *) 0);
	tvsub(&diff, &t, &start_tv);
	return (diff.tv_sec + diff.tv_usec / 1000000.0);
}

void
save_n(uint64 n)
{
	iterations = n;
}

uint64
get_n(void)
{
	return (iterations);
}

/*
 * Make the time spend be usecs.
 */
void
settime(uint64 usecs)
{
	bzero((void*)&start_tv, sizeof(start_tv));
	stop_tv.tv_sec = usecs / 1000000;
	stop_tv.tv_usec = usecs % 1000000;
}

void
setmeantime(double usecs)
{
  u_mean = usecs;
}

void
setvariancetime(double usecs)
{
  u_var = usecs;
}

void
setmeanratetime(double usecs)
{
  ops_s_mean = usecs;
}

void
setvarianceratetime(double usecs)
{
  ops_s_var = usecs;
}

void
bandwidth(uint64 bytes, uint64 times, int verbose)
{
	struct timeval tdiff;
	double  mb, secs;

	tvsub(&tdiff, &stop_tv, &start_tv);
	secs = tdiff.tv_sec;
	secs *= 1000000;
	secs += tdiff.tv_usec;
	secs /= 1000000;
	secs /= times;
	mb = bytes / MB;
	if (!ftiming) ftiming = stderr;
	if (verbose) {
		(void) fprintf(ftiming,
		    "%.4f MB in %.4f secs, %.4f MB/sec\n",
		    mb, secs, mb/secs);
	} else {
		if (mb < 1) {
			(void) fprintf(ftiming, "%.6f ", mb);
		} else {
			(void) fprintf(ftiming, "%.2f ", mb);
		}
		if (mb / secs < 1) {
			(void) fprintf(ftiming, "%.6f\n", mb/secs);
		} else {
			(void) fprintf(ftiming, "%.2f\n", mb/secs);
		}
	}
}

void
kb(uint64 bytes)
{
	struct timeval td;
	double  s, bs;

	tvsub(&td, &stop_tv, &start_tv);
	s = td.tv_sec + td.tv_usec / 1000000.0;
	bs = bytes / nz(s);
	if (!ftiming) ftiming = stderr;
	(void) fprintf(ftiming, "%.0f KB/sec\n", bs / KB);
}

void
mb(uint64 bytes)
{
	struct timeval td;
	double  s, bs;

	tvsub(&td, &stop_tv, &start_tv);
	s = td.tv_sec + td.tv_usec / 1000000.0;
	bs = bytes / nz(s);
	if (!ftiming) ftiming = stderr;
	(void) fprintf(ftiming, "%.2f MB/sec\n", bs / MB);
}

void
latency(uint64 xfers, uint64 size)
{
	struct timeval td;
	double  s;

	if (!ftiming) ftiming = stderr;
	tvsub(&td, &stop_tv, &start_tv);
	s = td.tv_sec + td.tv_usec / 1000000.0;
	if (xfers > 1) {
		fprintf(ftiming, "%d %dKB xfers in %.2f secs, ",
		    (int) xfers, (int) (size / KB), s);
	} else {
		fprintf(ftiming, "%.1fKB in ", size / KB);
	}
	if ((s * 1000 / xfers) > 100) {
		fprintf(ftiming, "%.0f millisec%s, ",
		    s * 1000 / xfers, xfers > 1 ? "/xfer" : "s");
	} else {
		fprintf(ftiming, "%.4f millisec%s, ",
		    s * 1000 / xfers, xfers > 1 ? "/xfer" : "s");
	}
	if (((xfers * size) / (MB * s)) > 1) {
		fprintf(ftiming, "%.2f MB/sec\n", (xfers * size) / (MB * s));
	} else {
		fprintf(ftiming, "%.2f KB/sec\n", (xfers * size) / (KB * s));
	}
}

void
context(uint64 xfers)
{
	struct timeval td;
	double  s;

	tvsub(&td, &stop_tv, &start_tv);
	s = td.tv_sec + td.tv_usec / 1000000.0;
	if (!ftiming) ftiming = stderr;
	fprintf(ftiming,
	    "%d context switches in %.2f secs, %.0f microsec/switch\n",
	    (int)xfers, s, s * 1000000 / xfers);
}

void
nano(char *s, uint64 n)
{
	struct timeval td;
	double  micro;

	tvsub(&td, &stop_tv, &start_tv);
	micro = td.tv_sec * 1000000 + td.tv_usec;
	micro *= 1000;
	if (!ftiming) ftiming = stderr;
	fprintf(ftiming, "%s: %.0f nanoseconds\n", s, micro / n);
}

/*
uint64
getmeantime(void)
{
        return (tvdelta(&start_tv, &stop_mean_tv));
}

uint64
getvariancetime(void)
{
        return (tvdelta(&start_tv, &stop_var_tv));
}
*/
static result_t results;
void
micro(char *s, uint64 n)
{
	struct timeval td;
	double	micro, mean, var;
	

	tvsub(&td, &stop_tv, &start_tv);
	micro = td.tv_sec * 1000000 + td.tv_usec;
	micro /= n;

	if (micro == 0.0) return;

	mean = getmeantime();
	var = getvariancetime();
	if (var < 0.0)
		var = 0.0;

	if (!ftiming) ftiming = stderr;
	fprintf(ftiming, "%s median=%.4lf [mean=%.4lf +/-%.4lf] microseconds\n",
		s, micro, mean,	ci_width(sqrt(var), results.N));
	fprintf(ftiming, "var: %lf sd: %lf runs: %d\n",
		var, sqrt(var), results.N);
}

void
micromb(uint64 sz, uint64 n)
{
	struct timeval td;
	double	mb, micro;

	tvsub(&td, &stop_tv, &start_tv);
	micro = td.tv_sec * 1000000 + td.tv_usec;
	micro /= n;
	mb = sz;
	mb /= MB;
	if (!ftiming) ftiming = stderr;
	if (micro >= 10) {
		fprintf(ftiming, "%.6f %.0f\n", mb, micro);
	} else {
		fprintf(ftiming, "%.6f %.3f\n", mb, micro);
	}
}

void
milli(char *s, uint64 n)
{
	struct timeval td;
	uint64 milli;

	tvsub(&td, &stop_tv, &start_tv);
	milli = td.tv_sec * 1000 + td.tv_usec / 1000;
	milli /= n;
	if (!ftiming) ftiming = stderr;
	fprintf(ftiming, "%s: %d milliseconds\n", s, (int)milli);
}

void
ptime(uint64 n)
{
	struct timeval td;
	double  s;

	tvsub(&td, &stop_tv, &start_tv);
	s = td.tv_sec + td.tv_usec / 1000000.0;
	if (!ftiming) ftiming = stderr;
	fprintf(ftiming,
	    "%d in %.2f secs, %.0f microseconds each\n",
	    (int)n, s, s * 1000000 / n);
}

uint64
tvdelta(struct timeval *start, struct timeval *stop)
{
	struct timeval td;
	uint64	usecs;

	tvsub(&td, stop, start);
	usecs = td.tv_sec;
	usecs *= 1000000;
	usecs += td.tv_usec;
	return (usecs);
}

void
tvsub(struct timeval * tdiff, struct timeval * t1, struct timeval * t0)
{
	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0 && tdiff->tv_sec > 0) {
		tdiff->tv_sec--;
		tdiff->tv_usec += 1000000;
		assert(tdiff->tv_usec >= 0);
	}

	/* time shouldn't go backwards!!! */
	if (tdiff->tv_usec < 0 || t1->tv_sec < t0->tv_sec) {
		tdiff->tv_sec = 0;
		tdiff->tv_usec = 0;
	}
}

double getmeantime(void)
{
  return u_mean;
}

double getvariancetime(void)
{
  return u_var;
}

double getmeanratetime(void)
{
  return ops_s_mean;
}

double getvarianceratetime(void)
{
  return ops_s_var;
}

/**
 * returns time in microseconds
 */
uint64
gettime(void)
{
	return (tvdelta(&start_tv, &stop_tv));
}

double
timespent(void)
{
	struct timeval td;

	tvsub(&td, &stop_tv, &start_tv);
	return (td.tv_sec + td.tv_usec / 1000000.0);
}

static	char	p64buf[10][20];
static	int	n;

char	*
p64(uint64 big)
{
	char	*s = p64buf[n++];

	if (n == 10) n = 0;
#ifdef  linux
	{
        int     *a = (int*)&big;

        if (a[1]) {
                sprintf(s, "0x%x%08x", a[1], a[0]);
        } else {
                sprintf(s, "0x%x", a[0]);
        }
	}
#endif
#ifdef	__sgi
        sprintf(s, "0x%llx", big);
#endif
	return (s);
}

char	*
p64sz(uint64 big)
{
	double	d = big;
	char	*tags = " KMGTPE";
	int	t = 0;
	char	*s = p64buf[n++];

	if (n == 10) n = 0;
	while (d > 512) t++, d /= 1024;
	if (d == 0) {
		return ("0");
	}
	if (d < 100) {
		sprintf(s, "%.4f%c", d, tags[t]);
	} else {
		sprintf(s, "%.2f%c", d, tags[t]);
	}
	return (s);
}

char
last(char *s)
{
	while (*s++)
		;
	return (s[-2]);
}

size_t
bytes(char *s)
{
	uint64	n;

	sscanf(s, "%llu", &n);

	if ((last(s) == 'k') || (last(s) == 'K'))
		n *= 1024;
	if ((last(s) == 'm') || (last(s) == 'M'))
		n *= (1024 * 1024);
	return ((size_t)n);
}

void
use_int(int result) { use_result_dummy += result; }

void
use_pointer(void *result) { use_result_dummy += *(int *)result; }

void
insertinit(result_t *r)
{
	int	i;

	r->N = 0;
	for (i = 0; i < TRIES; i++) {
		r->u[i] = 0;
		r->n[i] = 1;
	}
}

/* biggest to smallest */
void
insertsort(uint64 u, uint64 n, result_t *r)
{
	int	i, j;

	if (u == 0) return;

	for (i = 0; i < r->N; ++i) {
		if (u/(double)n > r->u[i]/(double)r->n[i]) {
			for (j = r->N; j > i; --j) {
				r->u[j] = r->u[j-1];
				r->n[j] = r->n[j-1];
			}
			break;
		}
	}
	r->u[i] = u;
	r->n[i] = n;
	r->N++;
}

//static result_t results;

void
print_results(int details)
{
	int	i;

	for (i = 0; i < results.N; ++i) {
		fprintf(stderr, "%.2f", (double)results.u[i]/results.n[i]);
		if (i < results.N - 1) fprintf(stderr, " ");
	}
	fprintf(stderr, "\n");
	if (details) {
		for (i = 0; i < results.N; ++i) {
			fprintf(stderr, 
				"%llu/%llu", results.u[i], results.n[i]);
			if (i < results.N - 1) fprintf(stderr, " ");
		}
		fprintf(stderr, "\n");
	}
		
}

void
get_results(result_t *r)
{
	*r = results;
}

/*
void
setmeantime(uint64 usecs)
{
        bzero((void*)&start_tv, sizeof(start_tv));
        stop_mean_tv.tv_sec = usecs / 1000000;
        stop_mean_tv.tv_usec = usecs % 1000000;
}

void
setvariancetime(uint64 usecs)
{
        bzero((void*)&start_tv, sizeof(start_tv));
        stop_var_tv.tv_sec = usecs / 1000000;
        stop_var_tv.tv_usec = usecs % 1000000;
}
*/
void
save_results(result_t *r)
{
	results = *r;
	save_median();
	save_mean();
	save_variance();
}

void
save_minimum()
{
	if (results.N == 0) {
		save_n(1);
		settime(0);
	} else {
		save_n(results.n[results.N - 1]);
		settime(results.u[results.N - 1]);
	}
}

void
save_median()
{
	int	i = results.N / 2;
	uint64	u, n;

	if (results.N == 0) {
		n = 1;
		u = 0;
	} else if (results.N % 2) {
		n = results.n[i];
		u = results.u[i];
	} else {
		n = (results.n[i] + results.n[i-1]) / 2;
		u = (results.u[i] + results.u[i-1]) / 2;
	}

	save_n(n); settime(u);
}

void
save_mean()
{
	int     i;
	double sum = 0;
	double sum_r = 0;
	double mean, mean_ops_s;
	if (results.N == 0) {
		mean = 0.;
		mean_ops_s = 0.;
	} else {
		for(i = 0; i < results.N; i++)
			sum += (double)results.u[i] / (double)results.n[i];

		mean = sum / (double)results.N;
		/* harmonic average for rates = n / (sum^n_{i=1} 1/rate_i) */
		mean_ops_s = ((double)results.N  * 1000000.) / sum;
	}
	setmeantime(mean);
	setmeanratetime(mean_ops_s);
}

double calc_variance(double mean, double *times, int size)
{
	unsigned int i;
	double sum;

	if (size <= 1)
		return 0;

	for (i = 0, sum = 0; i < size; i++)
		sum += (times[i] - mean) * (times[i] - mean);

	return sum / (double) (size - 1);
}

double calc_variance_rate(double mean, double *times, int size, 
			  int ops_per_measure)
{
	unsigned int i;
	double sum, x_r;

	if (size <= 1)
		return 0;

	for (i = 0, sum = 0; i < size; i++) {
		x_r = (double) ops_per_measure / (double) times[i];
		sum += (x_r - mean) * (x_r - mean);
	}

	return sum / (double) (size - 1);
}

double calc_mean(double *times, int size)
{
	unsigned int i;
	double sum;

	if (size <= 0)
		return 0;

	for (i = 0, sum = 0; i < size; i++)
		sum += times[i];

	return sum / (double) size;
}

double calc_mean_rate(double *times, int size, int ops_per_measure)
{
	int i;
	double sum;
	for(i = 0, sum = 0; i < size; i++)
		sum += times[i] / (double) ops_per_measure;

	/* harmonic average for rates = n / (sum^n_{i=1} 1/rate_i) */
	return ((double)size) / sum;
}

void
save_variance()
{
	double  mean, variance, sum;
	double  mean_r, variance_r, sum_r;
	int     i;

	if (results.N == 0) {
		sum = 0;
		mean = 0;
		variance = 0;
		sum_r = 0;
		mean_r = 0;
		variance_r = 0;
		goto done;
	} else {
		mean = getmeantime();
		mean_r = getmeanratetime();
		if (mean <= 0) {
			save_mean();
			mean = getmeantime();
			mean_r = getmeanratetime();
			if (mean <= 0) {
				variance = 0;
				variance_r = 0;
				goto done;
			}
		}

		for (i = 0, sum = 0; i < results.N; i++) {
			double x, x_r;

			x = (double)results.u[i] / (double)results.n[i];
			sum += (x-mean) * (x-mean);

			/* multiply by 1000000?: dividing by us, but want ops/s */
			x_r = ((double)results.n[i] * 1000000.) / (double)results.u[i];
			sum_r += (x_r-mean_r) * (x_r-mean_r);
		}

		if (results.N == 1) {
			variance = sum;
			variance_r = sum;
		} else {
			variance = sum / (double) (results.N - 1);
			variance_r = sum_r / (double) (results.N - 1);
		}
	}
done:
	setvariancetime(variance);
	setvarianceratetime(variance_r);
}

/*
 * The inner loop tracks bench.h but uses a different results array.
 */
static long *
one_op(register long *p)
{
	BENCH_INNER(p = (long *)*p, 0);
	return (p);
}

static long *
two_op(register long *p, register long *q)
{
	BENCH_INNER(p = (long *)*q; q = (long*)*p, 0);
	return (p);
}

static long	*p = (long *)&p;
static long	*q = (long *)&q;

double
l_overhead(void)
{
	int	i;
	uint64	N_save, u_save;
	static	double overhead;
	static	int initialized = 0;
	result_t one, two, r_save;

	init_timing();
	if (initialized) return (overhead);

	initialized = 1;
	if (getenv("LOOP_O")) {
		overhead = atof(getenv("LOOP_O"));
	} else {
		get_results(&r_save); N_save = get_n(); u_save = gettime(); 
		insertinit(&one);
		insertinit(&two);
		for (i = 0; i < TRIES; ++i) {
			use_pointer((void*)one_op(p));
			if (gettime() > t_overhead())
				insertsort(gettime() - t_overhead(), get_n(), &one);
			use_pointer((void *)two_op(p, q));
			if (gettime() > t_overhead())
				insertsort(gettime() - t_overhead(), get_n(), &two);
		}
		/*
		 * u1 = (n1 * (overhead + work))
		 * u2 = (n2 * (overhead + 2 * work))
		 * ==> overhead = 2. * u1 / n1 - u2 / n2
		 */
		save_results(&one); save_minimum();
		overhead = 2. * gettime() / (double)get_n();
		
		save_results(&two); save_minimum();
		overhead -= gettime() / (double)get_n();
		
		if (overhead < 0.) overhead = 0.;	/* Gag */

		save_results(&r_save); save_n(N_save); settime(u_save); 
	}
	return (overhead);
}

/*
 * Figure out the timing overhead.  This has to track bench.h
 */
uint64
t_overhead(void)
{
	uint64		N_save, u_save;
	static int	initialized = 0;
	static uint64	overhead = 0;
	struct timeval	tv;
	result_t	r_save;

	init_timing();
	if (initialized) return (overhead);

	initialized = 1;
	if (getenv("TIMING_O")) {
		overhead = atof(getenv("TIMING_O"));
	} else if (get_enough(0) <= 50000) {
		/* it is not in the noise, so compute it */
		int		i;
		result_t	r;

		get_results(&r_save); N_save = get_n(); u_save = gettime(); 
		insertinit(&r);
		for (i = 0; i < TRIES; ++i) {
			BENCH_INNER(gettimeofday(&tv, 0), 0);
			insertsort(gettime(), get_n(), &r);
		}
		save_results(&r);
		save_minimum();
		overhead = gettime() / get_n();

		save_results(&r_save); save_n(N_save); settime(u_save); 
	}
	return (overhead);
}

/*
 * Figure out how long to run it.
 * If enough == 0, then they want us to figure it out.
 * If enough is !0 then return it unless we think it is too short.
 */
static	int	long_enough;
static	int	compute_enough();

int
get_enough(int e)
{
	init_timing();
	return (long_enough > e ? long_enough : e);
}


static void
init_timing(void)
{
	static	int done = 0;

	if (done) return;
	done = 1;
	long_enough = compute_enough();
	t_overhead();
	l_overhead();
}

typedef long TYPE;

static TYPE **
enough_duration(register long N, register TYPE ** p)
{
#define	ENOUGH_DURATION_TEN(one)	one one one one one one one one one one
	while (N-- > 0) {
		ENOUGH_DURATION_TEN(p = (TYPE **) *p;);
	}
	return (p);
}

static uint64
duration(long N)
{
	uint64	usecs;
	TYPE   *x = (TYPE *)&x;
	TYPE  **p = (TYPE **)&x;

	start(0);
	p = enough_duration(N, p);
	usecs = stop(0, 0);
	use_pointer((void *)p);
	return (usecs);
}

/*
 * find the minimum time that work "N" takes in "tries" tests
 */
static uint64
time_N(long N)
{
	int     i;
	uint64	usecs;
	result_t r;

	insertinit(&r);
	for (i = 1; i < TRIES; ++i) {
		usecs = duration(N);
		insertsort(usecs, N, &r);
	}
	save_results(&r);
	save_minimum();
	return (gettime());
}

/*
 * return the amount of work needed to run "enough" microseconds
 */
static long
find_N(int enough)
{
	int		tries;
	static long	N = 10000;
	static uint64	usecs = 0;

	if (!usecs) usecs = time_N(N);

	for (tries = 0; tries < 10; ++tries) {
		if (0.98 * enough < usecs && usecs < 1.02 * enough)
			return (N);
		if (usecs < 1000)
			N *= 10;
		else {
			double  n = N;

			n /= usecs;
			n *= enough;
			N = n + 1;
		}
		usecs = time_N(N);
	}
	return (0);
}

/*
 * We want to verify that small modifications proportionally affect the runtime
 */
static double test_points[] = {1.015, 1.02, 1.035};
static int
test_time(int enough)
{
	int     i;
	long	N;
	uint64	usecs, expected, baseline, diff;

	if ((N = find_N(enough)) <= 0)
		return (0);

	baseline = time_N(N);

	for (i = 0; i < sizeof(test_points) / sizeof(double); ++i) {
		usecs = time_N((int)((double) N * test_points[i]));
		expected = (uint64)((double)baseline * test_points[i]);
		diff = expected > usecs ? expected - usecs : usecs - expected;
		if (diff / (double)expected > 0.0025)
			return (0);
	}
	return (1);
}


/*
 * We want to find the smallest timing interval that has accurate timing
 */
static int     possibilities[] = { 5000, 10000, 50000, 100000 };
static int
compute_enough()
{
	int     i;

	if (getenv("ENOUGH")) {
		return (atoi(getenv("ENOUGH")));
	}
	for (i = 0; i < sizeof(possibilities) / sizeof(int); ++i) {
		if (test_time(possibilities[i]))
			return (possibilities[i]);
	}

	/* 
	 * if we can't find a timing interval that is sufficient, 
	 * then use SHORT as a default.
	 */
	return (SHORT);
}

/*
 * This stuff isn't really lib_timing, but ...
 */
void
morefds(void)
{
#ifdef	RLIMIT_NOFILE
	struct	rlimit r;

	getrlimit(RLIMIT_NOFILE, &r);
	r.rlim_cur = r.rlim_max;
	setrlimit(RLIMIT_NOFILE, &r);
#endif
}

void
touch(char *buf, size_t nbytes)
{
	static size_t	psize;

	if (!psize) {
		psize = getpagesize();
	}
	while (nbytes > psize - 1) {
		*buf = 1;
		buf += psize;
		nbytes -= psize;
	}
}


#if defined(hpux) || defined(__hpux)
int
getpagesize()
{
	return (sysconf(_SC_PAGE_SIZE));
}
#endif

#ifdef WIN32
int
getpagesize()
{
	SYSTEM_INFO s;

	GetSystemInfo(&s);
	return ((int)s.dwPageSize);
}

LARGE_INTEGER
getFILETIMEoffset()
{
	SYSTEMTIME s;
	FILETIME f;
	LARGE_INTEGER t;

	s.wYear = 1970;
	s.wMonth = 1;
	s.wDay = 1;
	s.wHour = 0;
	s.wMinute = 0;
	s.wSecond = 0;
	s.wMilliseconds = 0;
	SystemTimeToFileTime(&s, &f);
	t.QuadPart = f.dwHighDateTime;
	t.QuadPart <<= 32;
	t.QuadPart |= f.dwLowDateTime;
	return (t);
}

int
gettimeofday(struct timeval *tv, struct timezone *tz)
{
	LARGE_INTEGER			t;
	FILETIME			f;
	double					microseconds;
	static LARGE_INTEGER	offset;
	static double			frequencyToMicroseconds;
	static int				initialized = 0;
	static BOOL				usePerformanceCounter = 0;

	if (!initialized) {
		LARGE_INTEGER performanceFrequency;
		initialized = 1;
		usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
		if (usePerformanceCounter) {
			QueryPerformanceCounter(&offset);
			frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
		} else {
			offset = getFILETIMEoffset();
			frequencyToMicroseconds = 10.;
		}
	}
	if (usePerformanceCounter) QueryPerformanceCounter(&t);
	else {
		GetSystemTimeAsFileTime(&f);
		t.QuadPart = f.dwHighDateTime;
		t.QuadPart <<= 32;
		t.QuadPart |= f.dwLowDateTime;
	}

	t.QuadPart -= offset.QuadPart;
	microseconds = (double)t.QuadPart / frequencyToMicroseconds;
	t.QuadPart = microseconds;
	tv->tv_sec = t.QuadPart / 1000000;
	tv->tv_usec = t.QuadPart % 1000000;
	return (0);
}
#endif

#ifdef KVM_LMBENCH
static int fd_pvclock_bench = -1;

int getbenchtimeofday(struct timeval *tv)
{
	//pvclock_bm_get tv;
	int ret = 0;

	if (fd_pvclock_bench < 0) {
		fd_pvclock_bench = open("/proc/pvclock/pvclock_bm_entry", O_RDONLY);
		if (fd_pvclock_bench < 0)
		{
			printf("Open error: \n");
			ret = -1;
			goto END;
		}
	}

	if(ioctl(fd_pvclock_bench, PVCLOCK_BM_GET, (unsigned long)tv) < 0)
	{
		printf ("IOCTL PVBLOCK_BM_GET error:\n");
		ret = -1;
		goto END;
	}

	//printf("pvclock bench succeeds: tv = {%ld, %ld}\n\n", tv->tv_sec, tv->tv_usec);

END:
	return ret;
}
#endif

void
TRACE(char* format, ...)
{
	va_list	ap;

	va_start(ap, format);
#ifdef _DEBUG
	vfprintf(stderr, format, ap);
	fflush(stderr);
#endif
	va_end(ap);
}
