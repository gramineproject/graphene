/*
 * $Id$
 */
#ifndef _TIMING_H
#define _TIMING_H

void setmeantime(double usecs);
void setvariancetime(double usecs);
double getvariancetime(void);
double getmeantime(void);

void setmeanratetime(double usecs);
void setvarianceratetime(double usecs);
double getvarianceratetime(void);
double getmeanratetime(void);

double calc_variance(double mean, double *times, int size);
double calc_variance_rate(double mean, double *times, int size, 
			  int ops_per_measure);
double calc_mean(double *times, int size);
double calc_mean_rate(double *times, int size, int ops_per_measure);

char	*p64(uint64 big);
char	*p64sz(uint64 big);
double	Delta(void);
double	Now(void);
void	adjust(int usec);
void	bandwidth(uint64 bytes, uint64 times, int verbose);
size_t	bytes(char *s);
void	context(uint64 xfers);
uint64	delta(void);
int	get_enough(int);
uint64	get_n(void);
void	kb(uint64 bytes);
double	l_overhead(void);
char	last(char *s);
void	latency(uint64 xfers, uint64 size);
void	mb(uint64 bytes);
void	micro(char *s, uint64 n);
void	micromb(uint64 mb, uint64 n);
void	milli(char *s, uint64 n);
void	morefds(void);
void	nano(char *s, uint64 n);
uint64	now(void);
void	ptime(uint64 n);
void	rusage(void);
void	save_n(uint64);
void	settime(uint64 usecs);
void	start(struct timeval *tv);
uint64	stop(struct timeval *begin, struct timeval *end);
uint64	t_overhead(void);
double	timespent(void);
void	timing(FILE *out);
uint64	tvdelta(struct timeval *, struct timeval *);
void	tvsub(struct timeval *tdiff, struct timeval *t1, struct timeval *t0);
void	print_results(int details);
void	use_int(int result);
void	use_pointer(void *result);
uint64	usecs_spent(void);
void	touch(char *buf, size_t size);

#if defined(hpux) || defined(__hpux) || defined(WIN32)
int	getpagesize();
#endif

#endif /* _TIMING_H */
