/*
 * disk - calculate zone bandwidths and seek times
 *
 * Usage: disk device
 *
 * Copyright (c) 1994-1997 Larry McVoy.  All rights reserved.
 * Bits of this are derived from work by Ethan Solomita.
 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	"bench.h"

#ifndef sgi
#define	NO_LSEEK64
#define	off64_t	long long
#endif
#define	SEEKPOINTS	2000
#define	ZONEPOINTS	150

uint64	disksize(char *);
int	seekto(int, uint64);
int	zone(char *disk, int oflag, int bsize);
int	seek(char *disk, int oflag);
#ifdef	linux
int	flushdisk(int);
#endif

int
main(int ac, char **av)
{
	fprintf(stderr, "\"Seek times for %s\n", av[1]);
	seek(av[1], 0);
	fprintf(stderr, "\n");
	fprintf(stderr, "\"Zone bandwidth for %s\n", av[1]);
	zone(av[1], 0, (1<<20));
	return (0);
}

int
zone(char *disk, int oflag, int bsize)
{
	char	*buf;
	int	usecs;
	int	error;
	int	n;
	int	fd;
	uint64	off;
	int	stride;

	if ((fd = open(disk, oflag)) == -1) {
		perror(disk);
		exit(1);
	}
	buf = valloc(bsize);
	if (!buf) {
		perror("valloc");
		exit(1);
	}
	bzero(buf, bsize);
#ifdef	linux
	flushdisk(fd);
#endif

	/*
	 * We want ZONEPOINTS data points 
	 * but the stride has to be at least 512 and a 512 multiple.
	 * Weird code below for precision.
	 */
	off = disksize(disk);
	off /= ZONEPOINTS;
	stride = off;
	if (stride < 512) stride = 512;
	stride += 511;
	stride >>= 9;
	stride <<= 9;

	/*
	 * Very small disks such as ZIP drives get a 256K blocksize.
	 * As measured on my SCSI ZIP, there seems to be no
	 * difference between 256K and 1MB for sequential reads.
	 * XXX - there is a rotational delay difference but that's tough.
	 */
	if (bsize > stride) bsize = 256<<10;
	if (bsize > stride) stride = bsize;

	off *= ZONEPOINTS;
	debug((stdout, "stride=%d bs=%d size=%dM points=%d\n",
	    stride, bsize, (int)(off >> 20), (int)(off/stride)));

	/*
	 * Read buf's worth of data every stride and time it.
	 * Don't include the rotational delay.
	 * This first I/O outside the loop is to catch read/write permissions.
	 */

#define	IO(a,b,c)	(oflag == 0 ? (n = read(a,b,c)) : (n = write(a,b,c)))

	error = IO(fd, buf, 512);
	if (error == -1) {
		perror(disk);
		exit(1);
	}
	off = 512;
	for ( ;; ) {
		if (IO(fd, buf, 1024) != 1024) {
			exit(0);
		}
		off += 1024;
		start(0);
		if (IO(fd, buf, bsize) != bsize) {
			exit(0);
		}
		usecs = stop(0, 0);
		off += bsize;
		fprintf(stderr, "%.01f %.2f\n",
		    off/1000000.0, (double)bsize/usecs);
		off += stride;
		if (seekto(fd, off)) {
			exit(0);
		}
	}
	exit(0);
}

/*
 * Seek - calculate seeks as a function of distance.
 */
#undef	IO
#define	IO(a,b,c)	error = (oflag == 0 ? read(a,b,c) : write(a,b,c)); \
			if (error == -1) { perror("io"); exit(1); }
#define	IOSIZE		512
#define	TOOSMALL	1000	/* seeks this small are cached */
#define	TOOBIG		1000000	/* seeks this big are remapped or weirdos */
				/* zip drives have seeks this long */

int
seek(char *disk, int oflag)
{
	char	*buf;
	int	fd;
	off64_t	size;
	off64_t	begin, end;
	int	usecs;
	int	error;
	int	tot_msec = 0, tot_io = 0;
	int	stride;

	if ((fd = open(disk, oflag)) == -1) {
		perror(disk);
		return (-1);
	}
#ifdef	linux
	flushdisk(fd);
#endif
	size = disksize(disk);
	buf = valloc(IOSIZE);
	bzero(buf, IOSIZE);

	/*
	 * We flip back and forth, in strides of 1MB (typically).
	 * If we have a 100MB fd, that means we do
	 * 1, 99, 2, 98, etc.
	 *
	 * We want around SEEK POINTS data points 
	 * but the stride has to be at least 512 and a 512 multiple.
	 */
	stride = size / SEEKPOINTS;
	if (stride < 512) stride = 512;
	stride += 511;
	stride >>= 9;
	stride <<= 9;

	debug((stdout, "stride=%d size=%dM points=%d\n",
	    stride, (int)(size >> 20), (int)(size/stride)));

	end = size;
	begin = 0;
	seekto(fd, begin);
	IO(fd, buf, IOSIZE);
	while (end >= begin + stride*2) {
		end -= stride;
		start(0);
		seekto(fd, end);
		IO(fd, buf, IOSIZE);
		usecs = stop(0, 0);
		if (usecs > TOOSMALL && usecs < TOOBIG) {
			tot_io++; tot_msec += usecs/1000;
			fprintf(stderr, "%.01f %.02f\n",
			    (end - begin - stride) / 1000000., usecs/1000.);
		}

		begin += stride;
		start(0);
		seekto(fd, begin);
		IO(fd, buf, IOSIZE);
		usecs = stop(0, 0);
		if (usecs > TOOSMALL && usecs < TOOBIG) {
			tot_io++; tot_msec += usecs/1000;
			fprintf(stderr, "%.01f %.02f\n",
			    (end + stride - begin) / 1000000., usecs/1000.);
		}
	}
	/*
	 * This is wrong, it should take the 1/3 stroke seek average.
	avg_msec = (double)tot_msec/tot_io;
	fprintf(stderr, "Average time == %.04f\n", avg_msec);
	 */
	return (0);
}

/*
 * Calculate how big a device is.
 *
 * To avoid 32 bit problems, our units are MB.
 */
#define	FORWARD		(512<<20)
#define	FORWARD1	(64<<20)
#define	FORWARD2	(1<<20)

/*
 * Go forward in 1GB chunks until you can't.
 * Go backwards in 128MB chunks until you can.
 * Go forwards in 1MB chunks until you can't and return that -1.
 */
uint64
disksize(char *disk)
{
	int	fd = open(disk, 0);
	char	buf[512];
	uint64	off = 0;

	if (fd == -1) {
		perror("usage: disksize device");
		return(0);
	}
	/*
	 * Go forward until it doesn't work.
	 */
	for ( ;; ) {
		off += FORWARD;
		if (seekto(fd, off)) {
			debug((stdout, "seekto(%dM) failed\n", (int)(off>>20)));
			off -= FORWARD;
			break;
		}
		if ((read(fd, buf, sizeof(buf)) != sizeof(buf))) {
			debug((stdout, "read @ %dM failed\n", (int)(off>>20)));
			off -= FORWARD;
			break;
		}
	}

	for ( ;; ) {
		off += FORWARD1;
		if (seekto(fd, off)) {
			debug((stdout, "seekto(%dM) failed\n", (int)(off>>20)));
			off -= FORWARD1;
			break;
		}
		if ((read(fd, buf, sizeof(buf)) != sizeof(buf))) {
			debug((stdout, "read @ %dM failed\n", (int)(off>>20)));
			off -= FORWARD1;
			break;
		}
	}

	for ( ;; ) {
		off += FORWARD2;
		if (seekto(fd, off)) {
			debug((stdout, "seekto(%dM) failed\n", (int)(off>>20)));
			off -= FORWARD2;
			break;
		}
		if ((read(fd, buf, sizeof(buf)) != sizeof(buf))) {
			debug((stdout, "read @ %dM failed\n", (int)(off>>20)));
			off -= FORWARD2;
			break;
		}
	}

	debug((stdout, "disksize(%s) = %d MB\n", disk, (int)(off >> 20)));
	return (off);
}

#define	BIGSEEK	(1<<30)

int
seekto(int fd, uint64 off)
{
#ifdef	__linux__
	extern	loff_t llseek(int, loff_t, int);

	if (llseek(fd, (loff_t)off, SEEK_SET) == (loff_t)-1) {
		return(-1);
	}
	return (0);
#else
	uint64	here = 0;

	lseek(fd, 0, 0);
	while ((uint64)(off - here) > (uint64)BIGSEEK) {
		if (lseek(fd, BIGSEEK, SEEK_CUR) == -1) break;
		here += BIGSEEK;
	}
	assert((uint64)(off - here) <= (uint64)BIGSEEK);
	if (lseek(fd, (int)(off - here), SEEK_CUR) == -1) return (-1);
	return (0);
#endif
}
