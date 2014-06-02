#ifdef	linux
/*
 * flushdisk() - linux block cache clearing
 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/ioctl.h>
#include	<linux/fs.h>

int
flushdisk(int fd)
{
	int	ret = ioctl(fd, BLKFLSBUF, 0);
	usleep(100000);
	return (ret);
}

#endif

#ifdef	MAIN
int
main(int ac, char **av)
{
#ifdef	linux
	int	fd;
	int	i;

	for (i = 1; i < ac; ++i) {
		fd = open(av[i], 0);
		if (flushdisk(fd)) {
			exit(1);
		}
		close(fd);
	}
#endif
	exit(0);
}
#endif
