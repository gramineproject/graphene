/*
 * lat_pipe.c - pipe transaction test
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

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
	int	pid, p1[2], p2[2];
	char	c;

     	if (pipe(p1) == -1 || pipe(p2) == -1) {
		perror("pipe");
		exit(1);
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(1);
	}
	if (pid > 0) {
		/*
		 * One time around to make sure both processes are started.
		 */
		if (write(p1[1], &c, 1) != 1 || read(p2[0], &c, 1) != 1) {
			perror("read/write on pipe");
			exit(1);
		}
		BENCH(doit(p2[0], p1[1]), SHORT);
		micro("Pipe latency", get_n());
		kill(pid, 15);
	} else {
		for ( ;; ) {
			if (read(p1[0], &c, 1) != 1 ||
			    write(p2[1], &c, 1) != 1) {
				perror("read/write on pipe");
				exit(1);
			}
		}
	}
	return (0);
}
