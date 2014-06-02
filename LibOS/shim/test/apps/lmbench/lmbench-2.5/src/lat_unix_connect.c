/*
 * lat_unix_connect.c - simple UNIX connection latency test
 *
 * Three programs in one -
 *	server usage:	lat_connect -s
 *	client usage:	lat_connect hostname [N]
 *	shutdown:	lat_connect -hostname
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";
#include "bench.h"

void	server_main(int ac, char **av);
void	client_main(int ac, char **av);

void
doit()
{
	int	sock = unix_connect("/tmp/af_unix");
	close(sock);
}

int
main(int ac, char **av)
{
	if (ac > 1 && !strcmp(av[1], "-s")) {
		if (fork() == 0) {
			server_main(ac, av);
		}
		exit(0);
	} else {
		client_main(ac, av);
	}
	exit(0);
	/* NOTREACHED */
}

void
client_main(int ac, char **av)
{
	char	buf[256];

	if (ac != 1) {
		fprintf(stderr, "usage: %s\n", av[0]);
		exit(1);
	}

	BENCH(doit(), 100000);
	sprintf(buf, "UNIX connection cost ");
	micro(buf, get_n());
	exit(0);
	/* NOTREACHED */
}

void
server_main(int ac, char **av)
{
	int     newsock, sock;
	char	c;

	if (ac != 2) {
		fprintf(stderr, "usage: %s -s\n", av[0]);
		exit(1);
	}
	GO_AWAY;
	sock = unix_server("/tmp/af_unix");
	for (;;) {
		newsock = unix_accept(sock);
		c = 0;
		read(newsock, &c, 1);
		if (c && c == '0') {
			unix_done(sock, "/tmp/af_unix");
			exit(0);
		}
		close(newsock);
	}
	/* NOTREACHED */
}
