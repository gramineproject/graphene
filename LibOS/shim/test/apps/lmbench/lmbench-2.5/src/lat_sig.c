/*
 * lat_sig.c - signal handler test
 *
 * XXX - this benchmark requires the POSIX sigaction interface.  The reason
 * for that is that the signal handler stays installed with that interface.
 * The more portable signal() interface may or may not stay installed and
 * reinstalling it each time is expensive.
 *
 * XXX - should really do a two process version.
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include <math.h>
#include "bench.h"
#include "confidence.h"

int	caught, to_catch, n, pos;
double *times;
double	adj;
double  adj_mean, adj_var;
void	handler() { }

#define ITER_UNITS 50

void	prot() {

	if (++caught == to_catch) {
		double	u;
		double mean;
		double var;


		u = stop(0,0);
		u /= (double) to_catch;

		times[pos++] = u;
		
		mean = calc_mean(times, pos);
		fprintf(stderr, "mean=%.4f adj_mean=%.4f\n", mean, adj_mean);
		
		var = calc_variance(mean, times, pos);
		fprintf(stderr, "var=%.4f adj_var=%.4f\n", var, adj_var);

		mean -= adj_mean;
		var += adj_var;

		fprintf(stderr, "Protection fault: "
			"[mean=%.4lf +/-%.4lf] microseconds\n",
			mean, ci_width(sqrt(var), pos));

		exit(0);
	}

	if (caught == ITER_UNITS) {
		double	u;
		double mean;
		double var;

		u = stop(0,0);
		u /= (double) ITER_UNITS;
		
		times[pos++] = u;

		caught = 0;
		to_catch -= ITER_UNITS;

		start(0);
	}

}

double
overhead(double *mean, double *var)
{
	int	me = getpid();
	double	o;

	/*
	 * OS cost of sending a signal without actually sending one
	 */
	BENCH(kill(me, 0), 0);
	o = usecs_spent();
	o /= get_n();

	if (mean)
	  *mean = getmeantime();
	if (var)
	  *var = getvariancetime();

	return (o);
}

double
overhead_mean(void)
{
  
}

void
install(void)
{
	struct	sigaction sa, old;

	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);	
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, &old);
}
void
do_install(void)
{
	double u, mean, var;  

	/*
	 * Installation cost
	 */
	BENCH(install(), 0);
	u = usecs_spent();
	u /= get_n();

	mean = getmeantime();
	var = getvariancetime();

	fprintf(stderr, "Signal handler installation: median=%.3f "
		"[mean=%.4lf +/-%.4lf] microseconds\n",
		u, mean, ci_width(sqrt(var), TRIES));
}

void
do_catch(int report)
{
	int	me = getpid();
	struct	sigaction sa, old;
	double	u, mean, var;
	double sig_mean, sig_var;

	/*
	 * Cost of catching the signal less the cost of sending it
	 */
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);	
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, &old);
	BENCH(kill(me, SIGUSR1), 0);
	u = usecs_spent();
	mean = getmeantime();
	var = getvariancetime();

	u /= get_n();
	u -= overhead(&sig_mean, &sig_var);
	adj = u;
	n = SHORT/u;
	to_catch = n;
	
	mean -= sig_mean;
	var += sig_var;

	adj_mean = mean;
	adj_var = var;

	if (report) {
		fprintf(stderr,
			"Signal handler overhead: median=%.3f "
			"[mean=%.4lf +/-%.4lf] microseconds\n",
			u, mean, ci_width(sqrt(var), TRIES));
	}
}

void
do_prot(int ac, char **av)
{
	int	fd;
	struct	sigaction sa;
	char	*where;

	if (ac != 3) {
		fprintf(stderr, "usage: %s prot file\n", av[0]);          
		exit(1);
	}
	fd = open(av[2], 0);
	where = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if ((int)where == -1) {
		perror("mmap");
		exit(1);
	}
	/*
	 * Catch protection faults.
	 * Assume that they will cost the same as a normal catch.
	 */
	do_catch(0);
	sa.sa_handler = prot;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGSEGV, &sa, 0);
	sigaction(SIGBUS, &sa, 0);
	times = malloc(sizeof(double) * ceil(n / ITER_UNITS));
	start(0);
	*where = 1;
}


int
main(int ac, char **av)
{
	if (ac < 2) goto usage;

	if (!strcmp("install", av[1])) {
		do_install();
	} else if (!strcmp("catch", av[1])) {
		do_catch(1);
	} else if (!strcmp("prot", av[1])) {
		do_prot(ac, av);
	} else {
usage:		printf("Usage: %s install|catch|prot file\n", av[0]);
	}
	return(0);
}
