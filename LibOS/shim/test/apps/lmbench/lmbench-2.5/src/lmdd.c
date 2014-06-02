char	*id = "$Id: lmdd.c,v 1.23 1997/12/01 23:47:59 lm Exp $\n";
/*
 * defaults:
 *	bs=8k
 *	count=forever
 *	if=internal
 *	of=internal
 *	ipat=0
 *	opat=0
 *	mismatch=0
 *	rusage=0
 *	flush=0
 *	rand=0
 *	print=0
 *	direct=0
 *	rt=0
 *	rtmax=0
 *	wtmax=0
 *	rtmin=0
 *	wtmin=0
 *	label=""
 * shorthands:
 *	k, m, g are 2^10, 2^20, 2^30 multipliers.
 *	K, M, G are 10^3, 10^6, 10^9 multipliers.
 *	recognizes "internal" as an internal /dev/zero /dev/null file.
 *
 * Copyright (c) 1994-1998 by Larry McVoy.  All rights reserved.
 * See the file COPYING for the licensing terms.
 *
 * TODO - rewrite this entire thing from scratch.  This is disgusting code.
 */

#ifndef __Lynx__
#define	FLUSH
#endif

#include	<fcntl.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<sys/time.h>
#include	"bench.h"

#undef ALIGN
#define ALIGN(x, bs)    ((x + (bs - 1)) & ~(bs - 1))

#ifdef	FLUSH
#include	<sys/mman.h>
#include	<sys/stat.h>
void		flush(void);
#endif

#define	USE_VALLOC
#ifdef	USE_VALLOC
#define	VALLOC	valloc
#else
#define	VALLOC	malloc
#endif

#ifdef	__sgi
#	define	LSEEK(a,b,c)	(uint64)lseek64(a, (off64_t)b, c)
#	define	ATOL(s)		atoll(s)
#endif
#ifdef	linux
#	define	LSEEK(a,b,c)	(uint64)lseek64(a, (uint64)b, (uint64)c)
#	define	ATOL(s)		atoll(s)
#endif
#if	!defined(linux) && !defined(__sgi)
#	define	LSEEK(a,b,c)	(uint64)lseek(a, b, c)
#	define	ATOL(s)		atol(s)
#endif


int     awrite, poff, out, Print, Fsync, Sync, Flush, Bsize, ru;
uint64	Start, End, Rand, int_count;
int	hash;
int	Realtime, Notrunc;
int	Rtmax, Rtmin, Wtmax, Wtmin;
int	rthist[12];		/* histogram of read times */
int	wthist[12];		/* histogram of write times */
char	*Label;
uint64	*norepeat;
int	norepeats = -1;
#ifdef	USE_BDS
	bds_msg	*m1, *m2;
#endif

uint64	getarg();
int	been_there(uint64 off);
int	getfile(char *s, int ac, char **av);

char   *cmds[] = {
	"bs",			/* block size */
	"bufs",			/* use this many buffers round robin */
	"count",		/* number of blocks */
#ifdef	DBG
	"debug",		/* set external variable "dbg" */
#endif
#ifdef	O_DIRECT
	"direct",		/* direct I/O on input and output */
	"idirect",		/* direct I/O on input */
	"odirect",		/* direct I/O on output */
#endif
#ifdef	FLUSH
	"flush",		/* map in out and invalidate (flush) */
#endif
	"fork",			/* fork to do write I/O */
	"fsync",		/* fsync output before exit */
	"if",			/* input file */
	"ipat",			/* check input for pattern */
	"label",		/* prefix print out with this */
	"mismatch",		/* stop at first mismatch */
	"move",			/* instead of count, limit transfer to this */
	"of",			/* output file */
	"opat",			/* generate pattern on output */
	"print",		/* report type */
	"rand",			/* do randoms over the specified size */
				/* must be power of two, not checked */
	"poff",			/* Print the offsets as we do the io. */
#ifdef	RUSAGE
	"rusage",		/* dump rusage stats */
#endif
	"skip",			/* skip this number of blocks */
	"sync",			/* sync output before exit */
	"touch",		/* touch each buffer after the I/O */
#if	!defined(hpux)
	"usleep",		/* sleep this many usecs between I/O */
#endif
	"hash",			/* hash marks like FTP */
	"append",		/* O_APPEND */
	"rtmax",		/* read latency histogram max in mills */
	"wtmax",		/* write latency histogram max in mills */
	"rtmin",		/* read latency histogram max in mills */
	"wtmin",		/* write latency histogram max in mills */
	"realtime",		/* create files as XFS realtime files */
	"notrunc",		/* overwrite rather than truncing out file */
	"end",			/* limit randoms to this size near the
				 * Rand endpoints. */
	"start",		/* Add this to Rand */
	"time",			/* Run for this many seconds only. */
	"srand",		/* Seed the random number generator */
	"padin",		/* Pad an extra untimed block_size read */
#ifdef	USE_BDS
	"awrite",		/* use async writes and pipeline them. */
#endif
	"norepeat",		/* don't ever do the same I/O twice */
#ifdef	sgi
	"mpin",			/* pin the buffer */
#endif
	"timeopen",		/* include open time in results */
	"nocreate",		/* just open for writing, don't create/trunc it */
#ifdef	O_SYNC
	"osync",		/* O_SYNC */
#endif
	0,
};


void error(char *);
void    done();
#ifdef	DBG
extern int dbg;
#endif

int 
main(int ac, char **av)
{
	uint  *buf;
	uint  *bufs[10];
	int	nbufs, nextbuf = 0;
	int     Fork, misses, mismatch, outpat, inpat, in, timeopen, gotcnt;
	int	slp;
	uint64	skip, size, count;
	void	chkarg();
	int     i;
	uint64	off = 0;
	int	touch;
	int	time;
	int	mills;
	int	pad_in;
	int	pid = 0;
	struct timeval	start_tv;
	struct timeval	stop_tv;

	if (sizeof(int) != 4) {
		fprintf(stderr, "sizeof(int) != 4\n");
		exit(1);
	}
	for (i = 1; i < ac; ++i) {
		chkarg(av[i]);
	}
	signal(SIGINT, done);
	signal(SIGALRM, done);
	misses = mismatch = getarg("mismatch=", ac, av);
	inpat = getarg("ipat=", ac, av);
	outpat = getarg("opat=", ac, av);
	Bsize = getarg("bs=", ac, av);
	if (Bsize < 0)
		Bsize = 8192;
#if	!defined(hpux)
	slp = getarg("usleep=", ac, av);
#endif
	Fork = getarg("fork=", ac, av);
	Fsync = getarg("fsync=", ac, av);
	Sync = getarg("sync=", ac, av);
	Rand = getarg("rand=", ac, av);
	Start = getarg("start=", ac, av);
	End = getarg("end=", ac, av);
	time = getarg("time=", ac, av);
	if ((End != -1) && (Rand != -1) && (End > Rand)) {
		End = Rand;
	}
	if (getarg("srand=", ac, av) != -1) {
		srand48((long)getarg("srand=", ac, av));
	}
	poff = getarg("poff=", ac, av) != -1;
	Print = getarg("print=", ac, av);
	nbufs = getarg("bufs=", ac, av);
	Realtime = getarg("realtime=", ac, av);
	Rtmax = getarg("rtmax=", ac, av);
	if ((Rtmax != -1) && (Rtmax < 10))
		Rtmax = 10;
	Rtmin = getarg("rtmin=", ac, av);
	if ((Rtmax != -1) && (Rtmin == -1)) {
		Rtmin = 0;
	}
	Wtmax = getarg("wtmax=", ac, av);
	if ((Wtmax != -1) && (Wtmax < 10))
		Wtmax = 10;
	Wtmin = getarg("wtmin=", ac, av);
	if ((Wtmax != -1) && (Wtmin == -1)) {
		Wtmin = 0;
	}
	if ((Rtmin && !Rtmax) || (Wtmin && !Wtmax)) {
		fprintf(stderr, "Need a max to go with that min.\n");
		exit(1);
	}
	if ((Rtmin > Rtmax) || (Wtmin > Wtmax)) {
		fprintf(stderr,
		    "min has to be less than max, R=%d,%d W=%d,%d\n",
		    Rtmax, Rtmin, Wtmax, Wtmin);
		exit(1);
	}
	timeopen = getarg("timeopen=", ac, av);
	pad_in = getarg("padin=", ac, av);
	if (pad_in == -1) pad_in = 0;
	
	if (nbufs == -1) nbufs = 1;
	if (nbufs > 10) { printf("Too many bufs\n"); exit(1); }
#ifdef	DBG
	dbg = getarg("debug=", ac, av) != -1;
#endif
#ifdef	RUSAGE
	ru = getarg("rusage=", ac, av);
#endif
	touch = getarg("touch=", ac, av) != -1;
	hash = getarg("hash=", ac, av) != (uint64)-1;
	Label = (char *)getarg("label=", ac, av);
	count = getarg("count=", ac, av);
	size = getarg("move=", ac, av);
	if (size != (uint64)-1)
		count = size / Bsize;
	if (Rand != -1) {
		size = Rand - Bsize;
		size = ALIGN(size, Bsize);
	}

#ifdef	FLUSH
	Flush = getarg("flush=", ac, av);
#endif
	if (count == (uint64)-1)
		gotcnt = 0;
	else
		gotcnt = 1;
	int_count = 0;
	skip = getarg("skip=", ac, av);
	if (getarg("norepeat=", ac, av) != -1) {
		if (gotcnt) {
			norepeat = (uint64*)calloc(count, sizeof(uint64));
		} else {
			norepeat = (uint64*)calloc(10<<10, sizeof(uint64));
		}
	}

	if ((inpat != -1 || outpat != -1) && (Bsize & 3)) {
		fprintf(stderr, "Block size 0x%x must be word aligned\n", Bsize);
		exit(1);
	}
	if ((Bsize >> 2) == 0) {
		fprintf(stderr, "Block size must be at least 4.\n");
		exit(1);
	}
	for (i = 0; i < nbufs; i++) {
		if (!(bufs[i] = (uint *) VALLOC((unsigned) Bsize))) {
			perror("VALLOC");
			exit(1);
		}
		bzero((char *) bufs[i], Bsize);
#ifdef sgi
		if (getarg("mpin=", ac, av) != -1) {
			if (mpin((void *)bufs[i], (size_t)Bsize)) {
				perror("mpin for adam");
			}
		}
#endif
	}

	if (time != -1) {
		alarm(time);
	}
	if (timeopen != -1) {
		start(NULL);
	}
	in = getfile("if=", ac, av);
	out = getfile("of=", ac, av);
	if (timeopen == -1) {
		start(NULL);
	}
	if ((Rtmax != -1) && in < 0) {
		fprintf(stderr, "I think you wanted wtmax, not rtmax\n");
		exit(1);
	}
	if ((Wtmax != -1) && out < 0) {
		fprintf(stderr, "I think you wanted rtmax, not wtmax\n");
		exit(1);
	}
	if (skip != (uint64)-1) {
		off = skip;
		off *= Bsize;
		if (in >= 0) {
			LSEEK(in, off, 0);
		}
		if (out >= 0) {
			LSEEK(out, off, 0);
		}
		if (poff) {
			fprintf(stderr, "%s ", p64sz(off));
		}
	}
	for (;;) {
		register int moved;

		if (gotcnt && count-- <= 0) {
			done();
		}

		/*
		 * If End is set, it means alternate back and forth
		 * between the end points of Rand, doing randoms within
		 * the area 0..End and Rand-End..Rand
		 */
		if (End != -1) {
			static	uint64 start = 0;

			start = start ? 0 : Rand - End;
			do {
				off = drand48() * End;
				off = ALIGN(off, Bsize);
				off += start;
				if (Start != -1) {
					off += Start;
				}
			} while (norepeat && been_there(off));
			if (norepeat) {
				norepeat[norepeats++] = off;
				if (!gotcnt && (norepeats == 10<<10)) {
					norepeats = 0;
				}
			}
			if (in >= 0) {
				LSEEK(in, off, 0);
			}
			if (out >= 0) {
				LSEEK(out, off, 0);
			}
		}
		/*
		 * Set the seek pointer if doing randoms
		 */
		else if (Rand != -1) {
			do {
				off = drand48() * (size - Bsize);
				if (Start != -1) {
					off += Start;
				}
				off = ALIGN(off, Bsize);
			} while (norepeat && been_there(off));
			if (norepeat) {
				norepeat[norepeats++] = off;
			}
			if (!gotcnt && (norepeats == 10<<10)) {
				norepeats = 0;
			}
			if (in >= 0) {
				LSEEK(in, off, 0);
			}
			if (out >= 0) {
				LSEEK(out, off, 0);
			}
		}
		if (poff) {
			fprintf(stderr, "%s ", p64sz(off));
		}

		buf = bufs[nextbuf];
		if (++nextbuf == nbufs) nextbuf = 0;
		if (in >= 0) {
			if ((Rtmax != -1) || (Rtmin != -1)) {
				start(&start_tv);
			}
			moved = read(in, buf, Bsize);
			
			if (pad_in) { /* ignore this run, restart clock */
			    pad_in = 0;
			    count++;
			    start(NULL);
			    continue;
			}
			
			if ((Rtmax != -1) || (Rtmin != -1)) {
				int mics = stop(&start_tv, &stop_tv);
				
				mills = mics / 1000;
				if ((mills > Rtmax) || (mills < Rtmin)) {
					fprintf(stderr,
					  "READ: %.02f milliseconds offset %s\n",
						((float)mics) / 1000,
						p64sz(LSEEK(in, 0, SEEK_CUR)));
				}
				/*
				 * Put this read time in the histogram.
				 * The buckets are each 1/10th of Rtmax.
				 */
				if (mills >= Rtmax) {
					rthist[11]++;
				} else if (mills < Rtmin) {
					rthist[0]++;
				} else {
					int	step = (Rtmax - Rtmin) / 10;
					int	i;

					for (i = 1; i <= 10; ++i) {
						if (mills < i * step + Rtmin) {
							rthist[i]++;
							break;
						}
					}
				}
			}
		} else {
			moved = Bsize;
		}
		if (moved == -1) {
			perror("read");
		}
		if (moved <= 0) {
			done();
		}
		if (inpat != -1) {
			register int foo, cnt;

			for (foo = 0, cnt = moved/sizeof(int); cnt--; foo++) {
				if (buf[foo] != (uint) (off + foo*sizeof(int))) {
					fprintf(stderr,
					    "off=%u want=%x got=%x\n",
					    (uint)off,
					    (uint)(off + foo*sizeof(int)),
					    buf[foo]);
					if (mismatch != -1 && --misses == 0) {
						done();
					}
				}
			}
		}
		if ((in >= 0) && touch) {
			int	i;

			for (i = 0; i < moved; i += 4096) {
				((char *)buf)[i] = 0;
			}
		}
		if (out >= 0) {
			int	moved2;

			if (Fork != -1) {
				if (pid) {
					waitpid(pid, 0, 0);
				}
				if ((pid = fork())) {
					off += moved;
					int_count += (moved >> 2);
					continue;
				}
			}
			if (outpat != -1) {
				register int foo, cnt;

				for (foo = 0, cnt = moved/sizeof(int);
				    cnt--; foo++) {
					buf[foo] =
					    (uint)(off + foo*sizeof(int));
				}
			}
			if ((Wtmax != -1) || (Wtmin != -1)) { 
				start(&start_tv);
			}
#ifdef	USE_BDS
			/*
			 * The first time through, m1 & m2 are null.
			 * The Nth time through, we start the I/O into
			 * m2, and wait on m1, then switch.
			 */
			if (awrite) {
				if (m1) {
					m2 = bds_awrite(out, buf, moved);
					moved2 = bds_adone(out, m1);
					m1 = m2;
				} else {
					m1 = bds_awrite(out, buf, moved);
					goto writedone;
				}
			} else {
				moved2 = write(out, buf, moved);
			}
#else
			moved2 = write(out, buf, moved);
#endif

			if (moved2 == -1) {
				perror("write");
			}
			if (moved2 != moved) {
				fprintf(stderr, "write: wanted=%d got=%d\n",
				    moved, moved2);
				done();
			}
			if ((Wtmax != -1) || (Wtmin != -1)) {
				int mics = stop(&start_tv, &stop_tv);

				mills = mics / 1000;
				if ((mills > Wtmax) || (mills < Wtmin)) {
					fprintf(stderr,
					  "WRITE: %.02f milliseconds offset %s\n",
						((float)mics) / 1000,
						p64sz(LSEEK(out, 0, SEEK_CUR)));
				}
				/*
				 * Put this write time in the histogram.
				 * The buckets are each 1/10th of Wtmax.
				 */
				if (mills >= Wtmax) {
					wthist[11]++;
				} else if (mills < Wtmin) {
					wthist[0]++;
				} else {
					int	step = (Wtmax - Wtmin) / 10;
					int	i;

					for (i = 1; i <= 10; ++i) {
						if (mills < i * step + Wtmin) {
							wthist[i]++;
							break;
						}
					}
				}
			}

			if (moved2 == -1) {
				perror("write");
			}
			if (moved2 != moved) {
				done();
			}

			if (touch) {
				int	i;

				for (i = 0; i < moved; i += 4096) {
					((char *)buf)[i] = 0;
				}
			}
		}
#ifdef	USE_BDS
writedone:	/* for the first async write */
#endif
		off += moved;
		int_count += (moved >> 2);
#if	!defined(hpux)
		if (slp != -1) {
			usleep(slp);
		}
#endif
		if (hash) {
			fprintf(stderr, "#");
		}
		if (Fork != -1) {
			exit(0);
		}
	}
}

int
been_there(uint64 off)
{
	register int i;

	for (i = 0; i <= norepeats; ++i) {
		if (off == norepeat[i]) {
			fprintf(stderr, "norepeat on %u\n", (uint)off);
			return (1);
		}
	}
	return (0);
}

void 
chkarg(char *arg)
{
	int	i;
	char	*a, *b;

	for (i = 0; cmds[i]; ++i) {
		for (a = arg, b = cmds[i]; *a && *b && *a == *b; a++, b++)
			;
		if (*a == '=')
			return;
	}
	fprintf(stderr, "Bad arg: %s, possible arguments are: ", arg);
	for (i = 0; cmds[i]; ++i) {
		fprintf(stderr, "%s ", cmds[i]);
	}
	fprintf(stderr, "\n");
	exit(1);
	/*NOTREACHED*/
}

void 
done(void)
{
	int	i;
	int	step;
	int	size;

#ifdef	USE_BDS
	if (awrite && m1) {
		bds_adone(out, m1);
	}
#endif
	if (Sync > 0)
		sync();
	if (Fsync > 0)
		fsync(out);
#ifdef	FLUSH
	if (Flush > 0)
		flush();
#endif
	stop(NULL, NULL);
#ifdef	RUSAGE
	if (ru != -1)
		rusage();
#endif
	if (hash || poff) {
		fprintf(stderr, "\n");
	}
	if ((long)Label != -1) {
		fprintf(stderr, "%s", Label);
	}
	int_count <<= 2;
	switch (Print) {
	    case 0:	/* no print out */
	    	break;

	    case 1:	/* latency type print out */
		latency((uint64)(int_count / Bsize), (uint64)Bsize);
		break;

	    case 2:	/* microsecond per op print out */
		micro("", (uint64)(int_count / Bsize));
		break;

	    case 3:	/* kb / sec print out */
		kb(int_count);
		break;

	    case 4:	/* mb / sec print out */
		mb(int_count);
		break;

	    case 5:	/* Xgraph output */
		bandwidth(int_count, 1, 0);
		break;

	    default:	/* bandwidth print out */
		bandwidth(int_count, 1, 1);
		break;
	}
	if (Rtmax != -1) {
		printf("READ operation latencies\n");
		step = (Rtmax - Rtmin) / 10;
		if (rthist[0]) {
			printf("%d- ms: %d\n", Rtmin, rthist[0]);
		}
		for (i = 1, size = Rtmin; i <= 10; i++, size += step) {
			if (!rthist[i])
				continue;
			printf("%d to %d ms: %d\n",
			       size, size + step - 1, rthist[i]);
		}
		if (rthist[11]) {
			printf("%d+ ms: %d\n", Rtmax, rthist[11]);
		}
	}
	if (Wtmax != -1) {
		printf("WRITE operation latencies\n");
		step = (Wtmax - Wtmin) / 10;
		if (wthist[0]) {
			printf("%d- ms: %d\n", Wtmin, wthist[0]);
		}
		for (i = 1, size = Wtmin; i <= 10; i++, size += step) {
			if (!wthist[i])
				continue;
			printf("%d to %d ms: %d\n",
			       size, size + step - 1, wthist[i]);
		}
		if (wthist[11]) {
			printf("%d+ ms: %d\n", Wtmax, wthist[11]);
		}
	}
	exit(0);
}

uint64 
getarg(char *s, int ac, char **av)
{
	register uint64 len, i;

	len = strlen(s);

	for (i = 1; i < ac; ++i) {
		if (!strncmp(av[i], s, len)) {
			register uint64 bs = ATOL(&av[i][len]);

			switch (av[i][strlen(av[i]) - 1]) {
			    case 'K': bs *= 1000; break;
			    case 'k': bs <<= 10; break;
			    case 'M': bs *= 1000000; break;
			    case 'm': bs <<= 20; break;
			    case 'G': bs *= 1000000000L; break;
			    case 'g': bs <<= 30; break;
			}

			if (!strncmp(av[i], "label", 5)) {
				return (uint64)(&av[i][len]);	/* HACK */
			}
			if (!strncmp(av[i], "bs=", 3)) {
				return (uint64)(bs);
			}
			return (bs);
		}
	}
	return ((uint64)-1);
}

char	*output;

int 
getfile(char *s, int ac, char **av)
{
	register int ret, len, i;
	int	append = getarg("append=", ac, av) != -1;
	int	notrunc = getarg("notrunc=", ac, av) != -1;
	int	nocreate = getarg("nocreate=", ac, av) != -1;
#ifdef	O_SYNC
	int	osync = getarg("osync=", ac, av) != -1;
#endif
	int	oflags;

	len = strlen(s);

	for (i = 1; i < ac; ++i) {
		if (!strncmp(av[i], s, len)) {
			if (av[i][0] == 'o') {
				if (!strcmp("of=internal", av[i]))
					return (-2);
				if (!strcmp("of=stdout", av[i]))
					return (1);
				if (!strcmp("of=1", av[i]))
					return (1);
				if (!strcmp("of=-", av[i]))
					return (1);
				if (!strcmp("of=stderr", av[i]))
					return (2);
				if (!strcmp("of=2", av[i]))
					return (2);
				oflags = O_WRONLY;
				oflags |= (notrunc || append) ? 0 : O_TRUNC;
				oflags |= nocreate ? 0 : O_CREAT;
				oflags |= append ? O_APPEND : 0;
#ifdef O_SYNC
				oflags |= osync ? O_SYNC : 0;
#endif
				ret = open(&av[i][len], oflags,0644);
#ifdef	O_DIRECT
				if ((getarg("odirect=", ac, av) != -1) ||
				    (getarg("direct=", ac, av) != -1)) {
					close(ret);
					ret = open(&av[i][len], oflags|O_DIRECT);
					awrite =
					    getarg("awrite=", ac, av) != -1;
				}
#endif
				if (ret == -1)
					error(&av[i][len]);
#ifdef F_FSSETXATTR
				if (Realtime == 1) {
					struct fsxattr fsxattr;
				
					bzero(&fsxattr,sizeof(struct fsxattr));
					fsxattr.fsx_xflags = 0x1;
					if (fcntl(ret,F_FSSETXATTR,&fsxattr)){
						printf("WARNING: Could not make %s a real time file\n",
						       &av[i][len]);
					}
				}
#endif
				output = &av[i][len];
				return (ret);
			} else {
				if (!strcmp("if=internal", av[i]))
					return (-2);
				if (!strcmp("if=stdin", av[i]))
					return (0);
				if (!strcmp("if=0", av[i]))
					return (0);
				if (!strcmp("if=-", av[i]))
					return (0);
				ret = open(&av[i][len], 0);
#ifdef	O_DIRECT
				if ((getarg("idirect=", ac, av) != -1) ||
				    (getarg("direct=", ac, av) != -1)) {
					close(ret);
					ret = open(&av[i][len], O_RDONLY|O_DIRECT);
				}
#endif
				if (ret == -1)
					error(&av[i][len]);
				return (ret);
			}
		}
	}
	return (-2);
}

#ifdef	FLUSH
int 
warning(char *s)
{
	if ((long)Label != -1) {
		fprintf(stderr, "%s: ", Label);
	}
	perror(s);
	return (-1);
}

void
flush(void)
{
	int	fd;
	struct	stat sb;
	caddr_t	where;

	if (output == NULL || (fd = open(output, 2)) == -1) {
		warning("No output file");
		return;
	}
	if (fstat(fd, &sb) == -1 || sb.st_size == 0) {
		warning(output);
		return;
	}
	where = mmap(0, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	msync(where, sb.st_size, MS_INVALIDATE);
	munmap(where, sb.st_size);
}
#endif

void 
error(char *s)
{
	if ((long)Label != -1) {
		fprintf(stderr, "%s: ", Label);
	}
	perror(s);
	exit(1);
}

