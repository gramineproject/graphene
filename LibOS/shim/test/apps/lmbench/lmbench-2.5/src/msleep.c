#include "bench.h"

int
main(int ac, char **av)
{
#if	defined(sgi) || defined(sun) || defined(linux)
	usleep(atoi(av[1]) * 1000);
	return (0);
#else
	fd_set	set;
	int	fd;
	struct	timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = atoi(av[1]) * 1000;
	FD_ZERO(&set);
	FD_SET(0, &set);
	select(1, &set, 0, 0, &tv);
	return (0);
#endif
}
