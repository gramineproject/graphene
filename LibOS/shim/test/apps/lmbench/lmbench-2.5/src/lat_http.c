/*
 * lat_http.c - simple HTTP transaction latency test
 *
 * usage: lat_http hostname [port] < filelist
 *
 * Copyright (c) 1994-6 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

char	*buf;
int	debug;
int	echo;

int
http(char *server, char *file, int prog)
{
	int     sock;
	int     n;
	int	b = 0;

	sock = tcp_connect(server, prog, SOCKOPT_REUSE);
	sprintf(buf, "GET /%s HTTP/1.0\r\n\r\n\n", file);
	if (debug) {
		printf(buf);
	}
	write(sock, buf, strlen(buf));
	while ((n = read(sock, buf, XFERSIZE)) > 0) {
		b += n;
		if (echo) {
			write(1, buf, n);
		}
	}
	close(sock);
	if (debug) {
		printf("Got %d\n", b);
	}
	return (b);
}

void
killhttp(char *server, int prog)
{
	int     sock;

	sock = tcp_connect(server, prog, SOCKOPT_REUSE);
	write(sock, "EXIT", 4);
	close(sock);
}

void chop(register char *s) { while (*s && *s != '\n') s++; *s = 0; }

int
main(int ac, char **av)
{
	char	*server;
	int     i, prog;
	uint64	total = 0;
	uint64	usecs = 0;
	double	avg;
	char	*name = av[0];
	char	file[1024];

	if (ac > 1 && !strcmp("-d", av[1])) {
		debug++;
		ac--, av++;
	}
	if (ac > 1 && !strcmp("-e", av[1])) {
		echo++;
		ac--, av++;
	}
	if (ac < 2) {
		fprintf(stderr, "Usage: %s [-d] [-e] [-]serverhost [port] < list\n",
		    name);
		exit(1);
	}
	server = av[1];
	av++, ac--;	/* eat server */
	if (ac > 1 && atoi(av[ac - 1]) != 0) {
		prog = -atoi(av[ac - 1]);
		ac--;	/* eat port */
	} else {
		prog = -80;
	}
	if (server[0] == '-') {
		server++;
		killhttp(server, prog);
		exit(0);
	}
	i = 0;
	buf = valloc(XFERSIZE);
	bzero(buf, XFERSIZE);
	while (fgets(file, sizeof(file), stdin)) {
		chop(file);
		start(0);
		total += http(server, file, prog);
		usecs += stop(0,0);
		i++;
	}
	avg = total;
	avg /= (i - 1);
	if (avg > 1000) {
		avg /= 1000;
		fprintf(stderr, "Avg xfer: %.1fKB, ", avg);
	} else {
		fprintf(stderr, "Avg xfer %d, ", (int)avg);
	}
	settime(usecs);
	latency((uint64)1, total);
	exit(0);
}

