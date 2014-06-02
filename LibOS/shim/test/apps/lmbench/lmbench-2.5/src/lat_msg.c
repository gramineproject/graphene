/*
 * lat_msgqueue.c - simple message queue latency test
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

#include <sys/ipc.h>
#include <sys/msg.h>

int
create_q(int key)
{
	return msgget(key, IPC_CREAT|0600);
}

int
open_q(int key)
{
	return msgget(key, 0);
}

void
close_q(int id)
{
	msgctl(id, IPC_RMID, NULL);
}

void
create_close_q(int key)
{
	int	id = create_q(key);
	close_q(id);
}

void
create_open_close_q(int key)
{
	int	id = create_q(key);
	open_q(key);
	close_q(id);
}

void
create_server(int pipes[2])
{
	int	i, begin = 0, end = 0;
	int	key, id = 0;
	while (read(pipes[0], &key, sizeof(int)) == sizeof(int)) {
		if (id) close_q(id);
		id = create_q(key);
		if (write(pipes[1], &id, sizeof(int)) < sizeof(int)) {
			perror("write");
			exit(1);
		}
	}
	if (id) close_q(id);
}

int
client_create_q(int pipes[2], int key)
{
	int	id;
	if (write(pipes[1], &key, sizeof(int)) < sizeof(int)) {
		perror("write");
		exit(1);
	}
	if (read(pipes[0], &id, sizeof(int)) < sizeof(int)) {
		perror("read");
		exit(1);
	}
	return id;
}

int
client_create_open_q(int pipes[2], int key)
{
	int	id;
	if (write(pipes[1], &key, sizeof(int)) < sizeof(int)) {
		perror("write");
		exit(1);
	}
	if (read(pipes[0], &id, sizeof(int)) < sizeof(int)) {
		perror("read");
		exit(1);
	}
	return open_q(key);
}

void
send_q(int *id, int n)
{
	if (n % 5000 == 0) {
		close_q(*id);
		*id = create_q(0);
	}
	struct {
		long	mtype;
		char	mtext[1];
	} buf;
	buf.mtype = 1;
	msgsnd(*id, &buf, 1, 0);
}

void
receive_q(int id)
{
	struct {
		long	mtype;
		char	mtext[1];
	} buf;
	if (msgrcv(id, &buf, 1, 1, 0) < 1) {
		perror("msgrcv");
		exit(1);
	}
}

void
send_receive_q(int *id, int n)
{
	send_q(id, n);
	receive_q(*id);
}

void
send_server(int pipes[2], int *id)
{
	int	n;
	while (read(pipes[0], &n, sizeof(int)) == sizeof(int)) {
		send_q(id, n);
		if (write(pipes[1], id, sizeof(int)) < sizeof(int)) {
			perror("write");
			exit(1);
		}
	}
}

void
client_send_q(int pipes[2], int n)
{
	int	id;
	if (write(pipes[1], &n, sizeof(int)) < sizeof(int)) {
		perror("write");
		exit(1);
	}
	if (read(pipes[0], &id, sizeof(int)) < sizeof(int)) {
		perror("read");
		exit(1);
	}
}

void
client_send_receive_q(int pipes[2], int n)
{
	int	id;
	if (write(pipes[1], &n, sizeof(int)) < sizeof(int)) {
		perror("write");
		exit(1);
	}
	if (read(pipes[0], &id, sizeof(int)) < sizeof(int)) {
		perror("read");
		exit(1);
	}
	receive_q(id);
}

int
main(int ac, char **av)
{
	if (ac < 2) goto usage;

	if (!strcmp("create", av[1])) {
		int	i, cnt = 0;
		BENCH(create_close_q(++cnt), REAL_SHORT);
		micro("message queue creation and close latency", get_n());
	} else if (!strcmp("fork-create", av[1])) {
		if (fork() == 0) {
			int	i, cnt = 0;
			BENCH(create_close_q(++cnt), REAL_SHORT);
			micro("message queue creation lnd close atency after fork",
			      get_n());
			exit(0);
		}
		wait(NULL);
	} else if (!strcmp("open", av[1])) {
		int	i, cnt = 0;
		BENCHO(create_open_close_q(++cnt), create_close_q(++cnt), REAL_SHORT);
		micro("message queue open latency", get_n());
		for (i = 1 ; i <= cnt ; i++)
			close_q(open_q(i));
	} else if (!strcmp("fork-open", av[1])) {
		int pipes[4];
		if (pipe(pipes) < 0 || pipe(pipes + 2) < 0) {
			perror("pipe");
			exit(1);
		}
		if (fork() == 0) {
			close(pipes[0]); close(pipes[3]); pipes[0] = pipes[2];
			int	i, cnt = 0;
			BENCHO(client_create_open_q(pipes, ++cnt),
			       client_create_q(pipes, ++cnt), REAL_SHORT);
			micro("message queue open latency after fork",
			      get_n());
			exit(0);
		}
		close(pipes[1]); close(pipes[2]); pipes[1] = pipes[3];
		create_server(pipes);
	} else if (!strcmp("send", av[1])) {
		int	id = create_q(0);
		int	cnt = 0;
		BENCH(send_q(&id, ++cnt), REAL_SHORT);
		micro("message queue sending latency", get_n());
		close_q(id);
	} else if (!strcmp("fork-send", av[1])) {
		int	id = create_q(0);
		int	cnt = 0;
		if (fork() == 0) {
			BENCH(send_q(&id, ++cnt), REAL_SHORT);
			micro("message queue sending latency after fork",
			      get_n());
			close_q(id);
			exit(0);
		}
		wait(NULL);
	} else if (!strcmp("receive", av[1])) {
		int	id = create_q(0);
		int	cnt = 0;
		BENCHO(send_receive_q(&id, ++cnt), send_q(&id, ++cnt), REAL_SHORT);
		micro("message queue receiving latency", get_n());
		close_q(id);
	} else if (!strcmp("fork-receive", av[1])) {
		int	id = create_q(0);
		int	cnt = 0;
		int	pipes[4];
		if (pipe(pipes) < 0 || pipe(pipes + 2) < 0) {
			perror("pipe");
			exit(1);
		}
		if (fork() == 0) {
			close(pipes[0]); close(pipes[3]); pipes[0] = pipes[2];
			BENCHO(client_send_receive_q(pipes, ++cnt),
			       client_send_q(pipes, ++cnt), REAL_SHORT);
			micro("message queue receiving latency after fork",
			      get_n());
			exit(0);
		}
		close(pipes[1]); close(pipes[2]); pipes[1] = pipes[3];
		send_server(pipes, &id);
		close_q(id);
	} else {
usage:		printf("Usage: %s create|fork-create|open|fork-open"
		       "|send|fork-send|receive|fork-receive\n", av[0]);
	}
	return(0);
}
