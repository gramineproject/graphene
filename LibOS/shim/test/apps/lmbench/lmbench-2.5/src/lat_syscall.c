/*
 * lat_syscall.c - time simple system calls
 *
 * Copyright (c) 1996 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 */
char	*id = "$Id$\n";

#include "bench.h"
#define	FNAME "/usr/include/x86_64-linux-gnu/sys/types.h"

void
do_write(int fd, char *s)
{
	char	c;

	if (write(fd, &c, 1) != 1) {
		perror(s);
		return;
	}
}

void
do_read(int fd, char *s)
{
	char	c;

	if (read(fd, &c, 1) != 1) {
		perror(s);
		return;
	}
}

void
do_stat(char *s)
{
	struct	stat sbuf;

	if (stat(s, &sbuf) == -1) {
		perror(s);
		return;
	}
}

void
do_fstat(int fd)
{
	struct	stat sbuf;

	if (fstat(fd, &sbuf) == -1) {
		perror("fstat");
		return;
	}
}

void
do_openclose(char *s)
{
	int	fd;

	fd = open(s, 0);
	if (fd == -1) {
		perror(s);
		return;
	}
	close(fd);
}

int
main(int ac, char **av)
{
	int	fd;
	char	*file;

	if (ac < 2) goto usage;
	file = av[2] ? av[2] : FNAME;

	if (!strcmp("null", av[1])) {
		BENCH(getppid(), 0);
		micro("Simple syscall", get_n());
	} else if (!strcmp("write", av[1])) {
		file = av[2] ? av[2] : "/dev/null";
		fd = open(file, 1);
		if (fd == -1) {
			fprintf(stderr, "Write from %s: %s\n", file, strerror(errno));
			return(1);
		}
		BENCH(do_write(fd, file), 0);;
		micro("Simple write", get_n());
		close(fd);
	} else if (!strcmp("read", av[1])) {
		file = av[2] ? av[2] : "/dev/null";
		fd = open(file, 0);
		if (fd == -1) {
			fprintf(stderr, "Read from %s: %s\n", file, strerror(errno));
			return(1);
		}
		BENCH(do_read(fd, file), 0);
		micro("Simple read", get_n());
		close(fd);
	} else if (!strcmp("stat", av[1])) {
		BENCH(do_stat(file), 0);
		micro("Simple stat", get_n());
	} else if (!strcmp("fstat", av[1])) {
		fd = open(file, 0);
		BENCH(do_fstat(fd), 0);
		micro("Simple fstat", get_n());
	} else if (!strcmp("open", av[1])) {
		BENCH(do_openclose(file), 0);
		micro("Simple open/close", get_n());
	} else {
usage:		printf("Usage: %s null|read|write|stat|open\n", av[0]);
	}
	return(0);
}
