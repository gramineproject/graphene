/*
 * tcp_xact.c - simple TCP transaction latency test
 *
 * Three programs in one -
 *	server usage:	tcp_xact -s
 *	client usage:	tcp_xact hostname
 *	shutwn:	tcp_xact -hostname
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";
#include "bench.h"

void	client(int sock);
void	server(int sock);

int
main(int ac, char **av)
{
	int	sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
	}
	if (fork() == 0) {
		BENCH(client(sv[1]), MEDIUM);
		micro("AF_UNIX sock stream latency", get_n());
		kill(getppid(), SIGTERM);
	} else {
		server(sv[0]);
	}
	return(0);
}

void
client(int sock)
{
	char    c;

	write(sock, &c, 1);
	read(sock, &c, 1);
}

void
server(int sock)
{
	char    c;
	int	n = 0;
	void	exit();

	signal(SIGTERM, exit);
	while (read(sock, &c, 1) == 1) {
		write(sock, &c, 1);
		n++;
	}
}
