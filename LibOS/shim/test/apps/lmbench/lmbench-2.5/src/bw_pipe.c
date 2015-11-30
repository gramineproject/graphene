/*
 * bw_pipe.c - pipe bandwidth benchmark.
 *
 * Usage: bw_pipe
 *
 * Copyright (c) 1994 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Support for this development by Sun Microsystems is gratefully acknowledged.
 */
char	*id = "$Id$\n";

#include "bench.h"

void	reader(int controlfd, int pipefd, size_t bytes);
void	writer(int controlfd, int pipefd);

size_t	XFER	= 10*1024*1024;
int	pid;
char	*buf;

int
main()
{
	int	pipes[2];
	int	control[2];

	if (pipe(pipes) == -1) {
		perror("pipe");
		return(1);
	}
	if (pipe(control) == -1) {
		perror("pipe");
		return(1);
	}
	switch (pid = fork()) {
	    case 0:
		close(control[1]);
		close(pipes[0]);
		buf = (char*)valloc(XFERSIZE);
		if (buf == NULL) {
			perror("no memory");
			return(1);
		}
		touch(buf, XFERSIZE);
		writer(control[0], pipes[1]);
		return(0);
		/*NOTREACHED*/
	    
	    case -1:
		perror("fork");
		return(1);
		/*NOTREACHED*/

	    default:
		break;
	}
	close(control[0]);
	close(pipes[1]);
	buf = (char*)valloc(XFERSIZE + getpagesize());
	if (buf == NULL) {
		perror("no memory");
		return(1);
	}
	touch(buf, XFERSIZE + getpagesize());
	buf += 128;	/* destroy page alignment */
	BENCH(reader(control[1], pipes[0], XFER), MEDIUM);
	fprintf(stderr, "Pipe bandwidth: ");
	mb(get_n() * XFER);
	kill(pid, 15);
	return(0);
}

void
writer(int controlfd, int pipefd)
{
	size_t	todo;
	size_t	bufsize = XFERSIZE;
	ssize_t	n;

	for ( ;; ) {
		bufsize = XFERSIZE;
		n = read(controlfd, &todo, sizeof(todo));
		if (n < 0) perror("writer::read");
		while (todo > 0) {
			if (todo < bufsize) bufsize = todo;
#ifdef	TOUCH
			touch(buf, bufsize);
#endif
			n = write(pipefd, buf, bufsize);
			if (n <= 0) {
				perror("writer::write");
				break;
			}
			todo -= n;
		}
	}
}

void
reader(int controlfd, int pipefd, size_t bytes)
{
	int	done = 0;
	size_t	todo = bytes;
	size_t	bufsize = XFERSIZE;
	ssize_t	n;

	n = write(controlfd, &bytes, sizeof(bytes));
	if (n < 0) perror("reader::write");
	while ((done < todo) && ((n = read(pipefd, buf, bufsize)) > 0)) {
		done += n;
		if (todo - done < bufsize) bufsize = todo - done;
	}
	if (n < 0) perror("reader::write");
	if (done < bytes) {
		fprintf(stderr, "reader: bytes=%ld, done=%d, todo=%ld\n", bytes, done, todo);
	}
}

