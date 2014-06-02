/*
 * lat_ctx.c - context switch timer 
 *
 * usage: lat_ctx [-s size] #procs [#procs....]
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

#if	defined(sgi) && defined(PIN)
#include <sys/sysmp.h>
#include <sys/syssgi.h>
int	ncpus;
#endif

#define	MAXPROC	2048
#define	CHUNK	(4<<10)
#define	TRIPS	5
#ifndef	max
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

int	process_size, *data;	/* size & pointer to an array that big */
int	pids[MAXPROC];
int	p[MAXPROC][2];
double	pipe_cost(int p[][2], int procs);
int	ctx(int procs, int nprocs);
int	sumit(int);
void	killem(int procs);
void	doit(int p[MAXPROC][2], int rd, int wr);
int	create_pipes(int p[][2], int procs);
int	create_daemons(int p[][2], int pids[], int procs);

int
main(int ac, char **av)
{
	int	i, max_procs;
	double	overhead = 0;

	if (ac < 2) {
usage:		printf("Usage: %s [-s kbytes] processes [processes ...]\n",
		    av[0]);
		exit(1);
	}

	/*
	 * Need 4 byte ints.
	 */
	if (sizeof(int) != 4) {
		fprintf(stderr, "Fix sumit() in ctx.c.\n");
		exit(1);
	}

	/*
	 * If they specified a context size, get it.
	 */
	if (!strcmp(av[1], "-s")) {
		if (ac < 4) {
			goto usage;
		}
		process_size = atoi(av[2]) * 1024;
		if (process_size > 0) {
			data = (int *)calloc(1, max(process_size, CHUNK));
			BENCHO(sumit(CHUNK), sumit(0), 0);
			overhead = gettime();
			overhead /= get_n();
			overhead *= process_size;
			overhead /= CHUNK;
		}
		ac -= 2;
		av += 2;
	}

#if	defined(sgi) && defined(PIN)
	ncpus = sysmp(MP_NPROCS);
	sysmp(MP_MUSTRUN, 0);
#endif
	for (max_procs = atoi(av[1]), i = 1; i < ac; ++i) {
		int procs = atoi(av[i]);
		if (max_procs < procs) max_procs = procs;
	}
	max_procs = create_pipes(p, max_procs);
	overhead += pipe_cost(p, max_procs);
	max_procs = create_daemons(p, pids, max_procs);
	fprintf(stderr, "\n\"size=%dk ovr=%.2f\n", process_size/1024, overhead);
	for (i = 1; i < ac; ++i) {
		double	time;
		int	procs = atoi(av[i]);

		if (procs > max_procs) continue;

		BENCH(ctx(procs, max_procs), 0);
		time = usecs_spent();
		time /= get_n();
		time /= procs;
		time /= TRIPS;
		time -= overhead;
	    	fprintf(stderr, "%d %.2f\n", procs, time);
	}

	/*
	 * Close the pipes and kill the children.
	 */
     	killem(max_procs);
     	for (i = 0; i < max_procs; ++i) {
		close(p[i][0]);
		close(p[i][1]);
		if (i > 0) {
			wait(0);
		}
	}
	return (0);
}


int
ctx(int procs, int nprocs)
{
	int	msg;
	int	i;
	int	sum;

	/*
	 * Main process - all others should be ready to roll, time the
	 * loop.
	 */
	for (i = 0; i < TRIPS; ++i) {
		if (write(p[nprocs - procs][1], &msg, sizeof(msg)) !=
		    sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			exit(1);
		}
		if (read(p[nprocs-1][0], &msg, sizeof(msg)) != sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			exit(1);
		}
		sum = sumit(process_size);
	}
	return (sum);
}

void
killem(int procs)
{
	int	i;

	for (i = 1; i < procs; ++i) {
		if (pids[i] > 0) {
			kill(pids[i], SIGTERM);
		}
	}
}

void
doit(int p[][2], int rd, int wr)
{
	int	msg, sum = 0 /* lint */;

	signal(SIGTERM, SIG_DFL);
	if (data) bzero((void*)data, process_size);	
	for ( ;; ) {
		if (read(p[rd][0], &msg, sizeof(msg)) != sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			break;
		}
		sum = sumit(process_size);
		if (write(p[wr][1], &msg, sizeof(msg)) != sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			break;
		}
	}
	use_int(sum);
	exit(1);
}

int
doit_cost(int p[][2], int procs)
{
	static	int k;
	int	msg = 1;
	int	i;

	for (i = 0; i < TRIPS; ++i) {
		if (write(p[k][1], &msg, sizeof(msg)) != sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			exit(1);				
		}
		if (read(p[k][0], &msg, sizeof(msg)) != sizeof(msg)) {
			if (errno) perror("read/write on pipe");
			exit(1);
		}
		if (++k == procs) {
			k = 0;
		}
	}
	return (msg);
}

/*
 * The cost returned is the cost of going through one pipe once in usecs.
 * No memory costs are included here, this is different than lmbench1.
 */
double
pipe_cost(int p[][2], int procs)
{
	double	result;

	/*
	 * Measure the overhead of passing a byte around the ring.
	 */
	BENCH(doit_cost(p, procs), 0);
	result = usecs_spent();
	result /= get_n();
	result /= TRIPS;
	return result;
}

int
create_daemons(int p[][2], int pids[], int procs)
{
	int	i, j;
	int	msg;

	/*
	 * Use the pipes as a ring, and fork off a bunch of processes
	 * to pass the byte through their part of the ring.
	 *
	 * Do the sum in each process and get that time before moving on.
	 */
	signal(SIGTERM, SIG_IGN);
	bzero(pids, procs * sizeof(pid_t));
     	for (i = 1; i < procs; ++i) {
		switch (pids[i] = fork()) {
		    case -1:	/* could not fork, out of processes? */
			procs = i;
			break;

		    case 0:	/* child */
#if	defined(sgi) && defined(PIN)
			sysmp(MP_MUSTRUN, i % ncpus);
#endif
			for (j = 0; j < procs; ++j) {
				if (j != i-1) close(p[j][0]);
				if (j != i) close(p[j][1]);
			}
			doit(p, i-1, i);
			/* NOTREACHED */

		    default:	/* parent */
			;
	    	}
	}

	/*
	 * Go once around the loop to make sure that everyone is ready and
	 * to get the token in the pipeline.
	 */
	if (write(p[0][1], &msg, sizeof(msg)) != sizeof(msg) ||
	    read(p[procs-1][0], &msg, sizeof(msg)) != sizeof(msg)) {
		if (errno) perror("write/read/write on pipe");
		exit(1);
	}
	if (data) bzero((void*)data, process_size);	
	return procs;
}

int
create_pipes(int p[][2], int procs)
{
	int	i;
	/*
	 * Get a bunch of pipes.
	 */
	morefds();
     	for (i = 0; i < procs; ++i) {
		if (pipe(p[i]) == -1) {
			return i;
		}
	}
	return procs;
}

/*
 * Bring howmuch data into the cache, assuming that the smallest cache
 * line is 16 bytes.
 */
int
sumit(int howmuch)
{
	int	done, sum = 0;
	register int *d = data;

#if 0
#define	A	sum+=d[0]+d[4]+d[8]+d[12]+d[16]+d[20]+d[24]+d[28]+\
		d[32]+d[36]+d[40]+d[44]+d[48]+d[52]+d[56]+d[60]+\
		d[64]+d[68]+d[72]+d[76]+d[80]+d[84]+d[88]+d[92]+\
		d[96]+d[100]+d[104]+d[108]+d[112]+d[116]+d[120]+d[124];\
		d+=128;
#define	TWOKB	A A A A
#else
#define	A	sum+=d[0]+d[1]+d[2]+d[3]+d[4]+d[5]+d[6]+d[7]+d[8]+d[9]+\
		d[10]+d[11]+d[12]+d[13]+d[14]+d[15]+d[16]+d[17]+d[18]+d[19]+\
		d[20]+d[21]+d[22]+d[23]+d[24]+d[25]+d[26]+d[27]+d[28]+d[29]+\
		d[30]+d[31]+d[32]+d[33]+d[34]+d[35]+d[36]+d[37]+d[38]+d[39]+\
		d[40]+d[41]+d[42]+d[43]+d[44]+d[45]+d[46]+d[47]+d[48]+d[49]+\
		d[50]+d[51]+d[52]+d[53]+d[54]+d[55]+d[56]+d[57]+d[58]+d[59]+\
		d[60]+d[61]+d[62]+d[63]+d[64]+d[65]+d[66]+d[67]+d[68]+d[69]+\
		d[70]+d[71]+d[72]+d[73]+d[74]+d[75]+d[76]+d[77]+d[78]+d[79]+\
		d[80]+d[81]+d[82]+d[83]+d[84]+d[85]+d[86]+d[87]+d[88]+d[89]+\
		d[90]+d[91]+d[92]+d[93]+d[94]+d[95]+d[96]+d[97]+d[98]+d[99]+\
		d[100]+d[101]+d[102]+d[103]+d[104]+\
		d[105]+d[106]+d[107]+d[108]+d[109]+\
		d[110]+d[111]+d[112]+d[113]+d[114]+\
		d[115]+d[116]+d[117]+d[118]+d[119]+\
		d[120]+d[121]+d[122]+d[123]+d[124]+d[125]+d[126]+d[127];\
		d+=128;	/* ints; bytes == 512 */
#define	TWOKB	A A A A
#endif

	for (done = 0; done < howmuch; done += 2048) {
		TWOKB
	}
	return (sum);
}
