#include "bench.h"

/*
 * lat_pipe.c - pipe transaction test
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id: lat_pipe.c,v 1.8 1997/06/16 05:38:58 lm Exp $\n";

#include "bench.h"

struct	flock lock, unlock;
struct	flock s1, s2;
int	fd1, fd2;

/*
 * Create two files, use them as a ping pong test.
 * Process A:
 *	lock(1)
 *	unlock(2)
 * Process B:
 *	unlock(1)
 *	lock(2)
 * Initial state:
 *	lock is locked
 *	lock2 is locked
 */

#define	waiton(fd)	fcntl(fd, F_SETLKW, &lock)
#define	release(fd)	fcntl(fd, F_SETLK, &unlock)

void
procA()
{
	if (waiton(fd1) == -1) {
		perror("lock of fd1 failed\n");
		exit(1);
	}
	if (release(fd2) == -1) {
		perror("unlock of fd2 failed\n");
		exit(1);
	}
	if (waiton(fd2) == -1) {
		perror("lock of fd2 failed\n");
		exit(1);
	}
	if (release(fd1) == -1) {
		perror("unlock of fd1 failed\n");
		exit(1);
	}
}

void
procB()
{
	if (release(fd1) == -1) {
		perror("unlock of fd1 failed\n");
		exit(1);
	}
	if (waiton(fd2) == -1) {
		perror("lock of fd2 failed\n");
		exit(1);
	}
	if (release(fd2) == -1) {
		perror("unlock of fd2 failed\n");
		exit(1);
	}
	if (waiton(fd1) == -1) {
		perror("lock of fd1 failed\n");
		exit(1);
	}
}

int
main()
{
	char	buf[10000];
	int	pid;

	unlink("/tmp/lmbench-fcntl.1");
	unlink("/tmp/lmbench-fcntl.2");
	if ((fd1 = open("/tmp/lmbench-fcntl.1", O_CREAT|O_RDWR, 0666)) == -1) {
		perror("create");
		exit(1);
	}
	if ((fd2 = open("/tmp/lmbench-fcntl.2", O_CREAT|O_RDWR, 0666)) == -1) {
		perror("create");
		exit(1);
	}
	unlink("/tmp/lmbench-fcntl.1");
	unlink("/tmp/lmbench-fcntl.2");
	write(fd1, buf, sizeof(buf));
	write(fd2, buf, sizeof(buf));
	lock.l_type = F_WRLCK;
	lock.l_whence = 0;
	lock.l_start = 0;
	lock.l_len = 1;
	unlock = lock;
	unlock.l_type = F_UNLCK;
	if (waiton(fd1) == -1) {
		perror("lock1");
		exit(1);
	}
	if (waiton(fd2) == -1) {
		perror("lock2");
		exit(1);
	}
	switch (pid = fork()) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		for ( ;; ) {
			procB();
		}
		exit(0);
	default:
		break;
	}
	BENCH(procA(), SHORT);
	micro("Fcntl lock latency", 2 * get_n());
	kill(pid, 15);
	return (0);
}
