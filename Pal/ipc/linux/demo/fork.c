#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "../graphene-ipc.h"

#define PAGE_SIZE 4096
#define MAX_PIDBUF 7
#define TEST_PAGES 20

struct mapping {
	unsigned long addr;
	unsigned long len;
	unsigned long perms;
	unsigned long flags;
};

int main(int argc, char **argv) 
{
	char *pages[TEST_PAGES];
	int p0[2];
	int64_t token;

	if (argc == 1) {
		// Server

		int pid;
		struct gipc_send gs;
		unsigned long addr[TEST_PAGES];
		unsigned long len[TEST_PAGES];
		int gfd;
		int i;
		int rv;

		/* Map some anonymous memory, fill with crap */
		for (i = 0; i < TEST_PAGES; i++) {
			pages[i] = mmap(NULL, PAGE_SIZE * TEST_PAGES, 
					PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if (!pages[i]) {
				perror("mmap");
				return -1;
			}

			memset(pages[i], 'a' + i, 256);
			pages[i][256] = '\0';
		}

		/* Set up a communications channel */
		if (pipe(p0) == -1) {
			printf("Pipe failed %d\n", errno);
			return -1;
		}


		/* fork + exec this program with an arg */
		pid = fork();
		if (pid == -1) {
			perror("Fork");
			return -1;
		} else if (pid == 0) {
			char *args[3];
			args[0] = argv[0];
			args[1] = "quack";
			args[2] = NULL;
			close(p0[1]);
			dup2(p0[0], 0);
			execv(argv[0], args);
			printf("Failed to EXEC %s %s!, %d\n", argv[0], args[0], errno);
			return -1;

		} 
		
		/* Parent */
		close (p0[0]);

		/* Open an IPC link */
		gfd = open (GIPC_FILE, O_RDWR);
		if (gfd < 0) {
			printf ("Fd is %d %d\n", gfd, errno);
			return -1;
		}

		token = ioctl(gfd, GIPC_CREATE, 0);
		if (token < 0) {
			printf ("Failed to create the gipc queue. %d\n", errno);
			return -1;
		}

		/* Write the token to the child */
		rv = write(p0[1], &token, sizeof(token));
		if  ( rv != sizeof(token)) {
			perror("Failed to write map size\n");
			return -1;
		}

		/* Send each region */
		gs.entries = TEST_PAGES;
		gs.addr = addr;
		gs.len = len;

		i = TEST_PAGES;
		rv = write(p0[1], &i, sizeof(int));
		if  ( rv != sizeof(int)) {
			perror("Failed to write map size\n");
			return -1;
		}

		for (i = 0; i < TEST_PAGES; i++) {
			struct mapping map = {(unsigned long) pages[i],
					      TEST_PAGES * PAGE_SIZE,
					      PROT_READ|PROT_WRITE,
					      MAP_PRIVATE|MAP_ANONYMOUS};

			rv = write(p0[1], &map, sizeof(map));
			if  ( rv != sizeof(map)) {
				perror("Failed to write map\n");
				return -1;
			}

			addr[i] = (unsigned long) pages[i];
			len[i] = TEST_PAGES * PAGE_SIZE;
		}		

		rv = ioctl(gfd, GIPC_SEND, &gs);
		if (rv)
			printf ("[server] Bad rv %d (2)\n", errno);

		close (gfd);
		close (p0[1]);

		/* Exit */
		wait();

	} else {

		int rv, gfd;
		int max, i;
		struct gipc_recv gr;

		/* Read the token from parent */
		rv = read(0, &token, sizeof(token));
		if (rv != sizeof(token)) {
			perror ("Size read failed\n");
			return -1;
		}

		/* Open the gipc channel */
		gfd = open (GIPC_FILE, O_RDWR);
		if (gfd < 0) {
			printf ("Fd is %d %d\n", gfd, errno);
			return -1;
		}

		/* Join the queue */
		rv = ioctl(gfd, GIPC_JOIN, token);
		if (rv < 0) {
			printf ("Failed to join GIPC queue - %d\n", errno);
			return -1;
		}

		/* Read count of descriptors */
		rv = read(0, &max, sizeof(int));
		if (rv != sizeof(int)) {
			perror ("Size read failed\n");
			return -1;
		}


		/* For each memory descriptor on the pipe */
		for (i = 0; i < max; i++) {
			struct mapping map;

			rv = read(0, &map, sizeof(map));
			if (rv != sizeof(map)) {
				perror ("Size read failed\n");
				return -1;
			}

			gr.len = map.len;
			gr.addr = map.addr;
			// Perms?

			/* map the memory */
			rv = ioctl(gfd, GIPC_RECV, &gr);
			if (rv) {
				printf ("Bad map %p rv %d %d\n", (void *)gr.addr, rv, errno);
				return 1;
			}

			/* Do some sanity checks that it worked */
			if ('a' + i != ((char *) map.addr)[250]) {
				printf("Failed to map right shiz\n");
				return -1;
			}

			printf("%s\n", (char *) map.addr);
		}

		close(gfd);
	}
	
	return 0;
}
