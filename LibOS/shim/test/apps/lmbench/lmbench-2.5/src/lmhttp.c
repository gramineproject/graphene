/*
 * http_srv.c - simple HTTP "server"
 *
 * Only implements the simplest GET operation.
 *
 * usage: http_srv [-f#] [-l] [-d] [port]
 *
 * Copyright (c) 1994-6 Larry McVoy.  Distributed under the FSF GPL with
 * additional restriction that results may published only if
 * (1) the benchmark is unmodified, and
 * (2) the version in the sccsid below is included in the report.
 * Other authors: Steve Alexander, sca@sgi.com.
 */
char	*id = "$Id$\n";

#ifdef	sgi
#include <sys/sysmp.h>
#include <sys/syssgi.h>
#endif
#include "bench.h"
#ifdef MAP_FILE
#	define	MMAP_FLAGS	MAP_FILE|MAP_SHARED
#else
#	define	MMAP_FLAGS	MAP_SHARED
#endif
#define	MMAPS_BETTER	(4<<10)	/* mmap is faster for sizes >= this */
#define	LOGFILE		"/usr/tmp/lmhttp.log"

char	*buf;
char	*bufs[3];
int	pflg, Dflg, dflg, nflg, lflg, fflg, zflg;
int	data, logfile;
void	die();
void	worker();
char	*http_time(void);
char	*date(time_t *tt);
char	*type(char *name);
int	source(int sock);
int	isdir(char *name);
void	dodir(char *name, int sock);
void	fake(int sock, char *buf, int size);
void	rdwr(int fd, int sock, char *buf);
int	mmap_rdwr(int from, int to, int size);
void	logit(int sock, char *name, int size);


int
main(int ac, char **av)
{
	int	i, prog;
#ifdef	sgi
	int	ncpus = sysmp(MP_NPROCS);
#endif

	for (i = 1; i < ac; ++i) {
		if (av[i][0] != '-') {
			break;
		}
		switch (av[i][1]) {
		    case 'D': Dflg = 1; break;	/* Allow directories */
		    case 'd': dflg = 1; break;	/* debugging */
		    case 'f': fflg = atoi(&av[i][2]);
		   		 break;		/* # of threads */
		    case 'l': lflg = 1; break;	/* logging */
		    case 'n': nflg = 1; break;	/* fake file i/o */
		    case 'p': pflg = 1; break;	/* pin them */
		    case 'z': zflg = 1; break;	/* all files are 0 size */
		    default:
			fprintf(stderr, "Barf.\n");
			exit(1);
		}
	}
	if (getenv("DOCROOT")) {
		if (chdir(getenv("DOCROOT")) == -1) {
			perror(getenv("DOCROOT"));
			exit(1);
		}
	}
	if (atoi(av[ac - 1]) != 0) {
		prog = -atoi(av[ac - 1]);
	} else {
		prog = -80;
	}
	/*
	 * Steve - why is this here?
	 */
	signal(SIGPIPE, SIG_IGN);
	data = tcp_server(prog, SOCKOPT_REUSE);
	bufs[0] = valloc(XFERSIZE);
	bufs[1] = valloc(XFERSIZE);
	bufs[2] = valloc(XFERSIZE);
	logfile = open(LOGFILE, O_CREAT|O_APPEND|O_WRONLY, 0666);
	signal(SIGINT, die);
	signal(SIGHUP, die);
	signal(SIGTERM, die);
	for (i = 1; i < fflg; ++i) {
		if (fork() <= 0) {
#ifdef sgi
			if (pflg) sysmp(MP_MUSTRUN, i % ncpus);
#endif
			break;
		}
	}
#ifdef sgi
	if (pflg) sysmp(MP_MUSTRUN, i % ncpus);
#endif
	worker();
	return(0);
}

void
worker()
{
	int	newdata;
	int	next = 0;

	for (;;) {
		buf = bufs[next];
		if (++next == 3) next = 0;
		newdata = tcp_accept(data, SOCKOPT_REUSE);
		source(newdata);
		close(newdata);
	}
}

/*
 * "Tue, 28 Jan 97 01:20:30 GMT";
 *  012345678901234567890123456
 */
char	*http_time()
{
	time_t	tt;
	static	time_t save_tt;
	struct	tm *t;
	static	struct tm save_tm;
	static	char buf[100];

	time(&tt);		/* costs 10 usecs */
	if (tt == save_tt) {
		return (buf);
	}
	save_tt = tt;
	t = gmtime(&tt);	/* costs 21 usecs */
	if (buf[0] && (tt - save_tt < 3600)) {
		buf[22] = t->tm_sec / 10 + '0';
		buf[21] = t->tm_sec % 10 + '0';
		save_tm.tm_sec = t->tm_sec;
		if (save_tm.tm_min == t->tm_min) {
			return (buf);
		}
	}
	save_tm = *t;
	/* costs 120 usecs */
	strftime(buf, sizeof(buf), "%a, %d %b %y %H:%M:%S %Z", t);
	return(buf);
}

/*
 * Input: dates that are probably within the last year.
 * Output: Tue, 28 Jan 97 01:20:30 GMT
 *
 * Since it costs 150 usecs or so to do this on an Indy, it may pay to
 * optimize this.  
 */
char	*
date(time_t	*tt)
{
	return "Tue, 28 Jan 97 01:20:30 GMT";
}

char	*
type(char *name)
{
	int	len = strlen(name);

	if (!strcmp(&name[len - 4], ".gif")) {
		return "image/gif";
	}
	if (!strcmp(&name[len - 5], ".jpeg")) {
		return "image/jpeg";
	}
	if (!strcmp(&name[len - 5], ".html")) {
		return "text/html";
	}
	if (Dflg && isdir(name)) {
		return "text/html";
	}
	return "text/plain";
}

/*
 * Read the file to be transfered.
 * Write that file on the data socket.
 * The caller closes the socket.
 */
int
source(int sock)
{
	int	fd, n, size;
	char	*s;
	char	file[100];
	char	hbuf[1024];
	struct	stat sb;
#define		name	&buf[5]

	n = read(sock, buf, XFERSIZE);
	if (n <= 0) {
		perror("control nbytes");
		return (-1);
	}
	buf[n] = 0;
	if (dflg) printf("%.*s\n", n, buf); 
	if (zflg) {
		return (0);
	}
	if (!strncmp(buf, "EXIT", 4)) {
		exit(0);
	}
	if (strncmp(buf, "GET /", 5)) {
		perror(buf);
		return(1);
	}
	for (s = buf; *s && *s != '\r' && *s != '\n'; s++)
		;
	*s = 0;
	for (s = name; *s && *s != ' '; s++) 
		;
	*s = 0;
	if (lflg) strncpy(file, name, sizeof(file));
	if (dflg) printf("OPEN %s\n", name);
	fd = open(name, 0);
	if (fd == -1) {
error:		perror(name);
		close(fd);
		return (1);
	}
	if (fstat(fd, &sb) == -1) {
		if (dflg) printf("Couldn't stat %s\n", name);
		goto error;
	}
	size = sb.st_size;
	n = sprintf(hbuf, "HTTP/1.0 200 OK\r\n%s\r\nServer: lmhttp/0.1\r\nContent-Type: %s\r\nLast-Modified: %s\r\n\r\n",
	    http_time(), type(name), date(&sb.st_mtime));
	if (write(sock, hbuf, n) != n) {
		goto error;
	}
	if (Dflg && isdir(name)) {
		dodir(name, sock);
	} else if (nflg) {
		fake(sock, buf, size);
	} else if ((size > MMAPS_BETTER)) {	/* XXX */
		if (mmap_rdwr(fd, sock, size) == -1) {
			printf("%s mmap failed\n", name);
		}
	} else {
		rdwr(fd, sock, buf);
	}
	if (lflg) logit(sock, file, size);
	close(fd);
	return(0);
}
#undef	name


int
isdir(char *name)
{
	struct	stat sb;
	if (stat(name, &sb) == -1) {
		return(0);
	}
	return (S_ISDIR(sb.st_mode));
}

#ifdef example
<HTML><HEAD>
<TITLE>Index of /pub/Linux</TITLE>
</HEAD><BODY>
<H1>Index of /pub/Linux</H1>
<PRE><IMG SRC="/icons/blank.gif" ALT="     "> Name                   Last modified     Size  Description
<HR>
<IMG SRC="/icons/unknown.gif" ALT="[   ]"> <A HREF="!INDEX">!INDEX</A>                 19-Sep-97 03:20     3k  
<IMG SRC="/icons/text.gif" ALT="[TXT]"> <A HREF="!INDEX.html">!INDEX.html</A>            19-Sep-97 03:20     6k  
#endif

void
dodir(char *name, int sock)
{
	FILE	*p;
	char	buf[1024];
	char	path[1024];

	if (dflg) printf("dodir(%s)\n", name);
	sprintf(buf, "cd %s && ls -1a", name);
	p = popen(buf, "r");
	if (!p && dflg) printf("Couldn't popen %s\n", buf);
	sprintf(buf, "\
<HTML><HEAD>\n<TITLE>Index of /%s</TITLE></HEAD><BODY><H1>Index of /%s</H1>\n",
	    name, name);
	write(sock, buf, strlen(buf));
	while (fgets(buf, sizeof(buf), p)) {
		buf[strlen(buf) - 1] = 0;
		sprintf(path, "/%s/%s", name, buf);
		if (dflg) printf("\t%s\n", path);
		write(sock, "<A HREF=\"", 9);
		write(sock, path, strlen(path));
		write(sock, "\">", 2);
		write(sock, buf, strlen(buf));
		write(sock, "</A><BR>\n", 9);
	}
	pclose(p);
}

void
fake(int sock, char *buf, int size)
{
	int	n;

	while (size > 0) {
		n = write(sock, buf, size > XFERSIZE ? XFERSIZE : size);
		if (n == -1) {
			perror("write on socket");
			return;
		}
		size -= n;
	}
}

void
rdwr(int fd, int sock, char *buf)
{
	int	nread;

	while ((nread = read(fd, buf, XFERSIZE)) > 0) {
		int	i;

		for (i = 0; i < nread; ) {
			int	nwrote = write(sock, buf, nread - i);

			if (i < 0) {
				exit(1);
			}
			i += nwrote;
		}
	}
}

int
mmap_rdwr(int from, int to, int size)
{
	char	*buf;
	int	done = 0, wrote;

	buf = mmap(0, size, PROT_READ, MMAP_FLAGS, from, 0);
	if ((int)buf == -1) {
		perror("mmap");
		return (-1);
	}
	do {
		wrote = write(to, buf + done, size - done);
		if (wrote == -1) {
			perror("write");
			break;
		}
		done += wrote;
	} while (done < size);
	if (munmap(buf, size) == -1) {
		perror("unmap");
	}
	return (0);
}

static	char logbuf[64<<10];	/* buffer into here */
static	int nbytes;		/* bytes buffered */

/*
 * HTTP server logging, compressed format.
 */
void
logit(int sock, char *name, int size)
{
	struct	sockaddr_in sin;
	int	len = sizeof(sin);
	char	buf[1024 + 16];		/* maxpathlen + others */

	if (getpeername(sock, (struct sockaddr*)&sin, &len) == -1) {
		perror("getpeername");
		return;
	}
	len = sprintf(buf, "%u %u %s %u\n",
	    *((unsigned int*)&sin.sin_addr), (unsigned int)time(0), name, size);
	if (nbytes + len >= sizeof(logbuf)) {
		write(logfile, logbuf, nbytes);
		nbytes = 0;
	}
	bcopy(buf, &logbuf[nbytes], len);
	nbytes += len;
}

void die()
{
	if (nbytes) {
		write(logfile, logbuf, nbytes);
		nbytes = 0;
	}
	exit(1);
}
