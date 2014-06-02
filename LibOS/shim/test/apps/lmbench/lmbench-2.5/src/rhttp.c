/*
 * rhttp.c - simple HTTP transaction latency test
 *
 * usage: rhttp hostname [port] remote-clients -p file file 
 *
 * This turns into a bunch of 
 *	rsh remote http hostname file file file [port]
 * with the results aggragated and reported.
 *
 * The program "http" must be in your path on the remote machine.
 *
 * XXX - the way this should work is like so:
 *	parent process reading file names from stdin
 *	multiple child processes connected to the parent process
 *	while more file names
 *		wait for a child process to be idle
 *		feed it ~10 filenames
 *	the child processes need to be able to tell the parent that they
 *	want more work.  They also need to pass back the results.
 *
 * Copyright (c) 1994-1997 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Silicon Graphics is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

int
main(int ac, char **av)
{
	char	*name = av[0], *server, *prog;
	int     i, j;
	uint64	total = 0;
	uint64	usecs = 0;
	char	*args[1024];

	if (ac < 5) {
usage:		fprintf(stderr,
		    "Usage: %s hostname [port] remote-clients -p file ...\n",
		    name);
		exit(1);
	}
	server = av[1];
	av++, ac--;	/* eat server */
	if (atoi(av[1]) != 0) {
		prog = av[1];
		av++, ac--;	/* eat port */
	} else {
		prog = "80";	/* http */
	}
	for (i = 1; i < ac; ++i) {
		if (!strcmp("-p", av[i])) {
			i++;
			break;
		}
	}
	args[0] = "rsh";
	args[2] = "http";
	args[3] = server;
	j = 4;
	while (i < ac) {
		args[j++] = av[i++];
	}
	args[j++] = prog;
	args[j] = 0;
	for (i = 1; i < ac; ++i) {
		if (!strcmp("-p", av[i])) {
			break;
		}
		args[1] = av[i];
		for (j = 0; args[j]; j++) {
			printf("%s ", args[j]);
		}
		printf("\n");
		if (fork() == 0) {
			char	name[30];

			sprintf(name, "/tmp/rhttp%d", i);
			creat(name, 0666);
			close(2);
			dup(1);
			execvp(args[0], args);
			perror(args[0]);
			exit(1);
		}
	}
	for (i = 1; i < ac; ++i) {
		if (!strcmp("-p", av[i])) {
			break;
		}
		wait(0);
	}
	system("cat /tmp/rhttp*; rm /tmp/rhttp*"); 
	exit(1);
	for (i = 1; i < ac; ++i) {
		int	fd, n, m = 0;
		float	f1 = 0, f2 = 0;
		char	buf[30];

		if (!strcmp("-p", av[i])) {
			break;
		}
		sprintf(buf, "/tmp/http%d", i);
		fd = open(buf, 0);
		unlink(buf);
		/* 
		 * Avg xfer: 3.9KB, 235.0KB in 2038 millisecs, 115.31 KB/sec
		 */
		n = read(fd, buf, XFERSIZE);
		buf[n] = 0;
		sscanf(buf, "Avg xfer: %fKB, %fKB in %d millisecs,", 
		    &f1, &f2, &m);
		if (m > usecs) {
			usecs = m;
		}
		total += f2;
	}
	total <<= 10;
	usecs *= 1000;
	settime(usecs);
	latency((uint64)1, total);
}
