/*
 * lat_fifo.c - named pipe transaction test
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include "bench.h"

#define	F1	"/tmp/lmbench_f1"
#define	F2	"/tmp/lmbench_f2"

void
doit(int r, int w)
{
	char	c;

	if (write(w, &c, 1) != 1 || read(r, &c, 1) != 1) {
			perror("read/write on pipe");
			exit(1);
	}
}

int
main()
{
	int	pid, rd, wr;
	char	c;

	unlink(F1); unlink(F2);
	if (mknod(F1, S_IFIFO|0664, 0) || mknod(F2, S_IFIFO|0664, 0)) {
		perror("mknod");
		exit(1);
	}
	switch (pid = fork()) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		wr = open(F1, O_WRONLY);
		rd = open(F2, O_RDONLY);
		for ( ;; ) {
			if (read(rd, &c, 1) != 1 ||
			    write(wr, &c, 1) != 1) {
				perror("read/write on FIFO");
				exit(1);
			}
		}
		exit(1);
	default:
		break;
	}
	rd = open(F1, O_RDONLY);
	wr = open(F2, O_WRONLY);
	/*
	 * One time around to make sure both processes are started.
	 */
	if (write(wr, &c, 1) != 1 || read(rd, &c, 1) != 1) {
		perror("read/write on FIFO");
		exit(1);
	}
	BENCH(doit(rd, wr), SHORT);
	micro("FIFO latency", get_n());
	kill(pid, 15);
	return (0);
}
