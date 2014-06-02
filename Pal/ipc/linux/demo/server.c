#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "../graphene-ipc.h"

#define PAGE_SIZE 4096
#define MAX_PIDBUF 20


int main () {
	volatile int * volatile x;
	int pid, pid2, fd0, fd1, rv;
	struct gipc_send gs;
	int p0[2];
	int p1[2];
	int p2[2];
	char pidbuf[MAX_PIDBUF];
	unsigned long addr[3];
	unsigned long len[3];
	int64_t token0, token1;
	int order = 0;

	if (pipe(p0) == -1) {
		printf("Pipe failed %d\n", errno);
		return -1;
	}

	if (pipe(p1) == -1) {
		printf("Pipe failed %d\n", errno);
		return -1;
	}

	if (pipe(p2) == -1) {
		printf("Pipe failed %d\n", errno);
		return -1;
	}

	/* Just fork the client as a convenient way to get the pid */
	pid = fork();
	if (pid == -1) {
		printf("Failed to FORK!, %d\n", errno);
		return -1;
	} else if (pid == 0) {
		// child reads the pipe
		close(p0[1]);
		dup2(p0[0], 0);
		dup2(p2[1], 3);
		execv("./client", NULL);
		printf("Failed to EXEC!, %d\n", errno);
		return -1;
	} else {
		close(p0[0]);
	}

	pid2 = fork();
	if (pid2 == -1) {
		printf("Failed to FORK!, %d\n", errno);
		return -1;
	} else if (pid2 == 0) {
		// child reads the pipe
		close(p1[1]);
		dup2(p1[0], 0);
		dup2(p2[0], 3);
		execv("./client", NULL);
		printf("Failed to EXEC!, %d\n", errno);
		return -1;
	} else {
		close(p1[0]);
	}

	printf("Server is %d, clients are %d %d\n", getpid(), pid, pid2);

	/* Map an anonymous page */
	addr[0] = (unsigned long) mmap(NULL, PAGE_SIZE * 6, PROT_READ|PROT_WRITE, 
				       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	x = (int *) addr[0];
	addr[1] = addr[0] + PAGE_SIZE;
	addr[2] = addr[1] + PAGE_SIZE;
	len[0] = PAGE_SIZE;
	len[1] = PAGE_SIZE;
	len[2] = PAGE_SIZE;

	/* Put a 42 in it */
	*x = pid2;
	x += PAGE_SIZE / sizeof(int);
	*x = 13;
	x += PAGE_SIZE / sizeof(int);
	*x = 407;
	x += PAGE_SIZE / sizeof(int);
	*x = pid;
	x += PAGE_SIZE / sizeof(int);
	*x = 155;
	x += PAGE_SIZE / sizeof(int);
	*x = 48;

	/* Open an IPC link */
	fd0 = open (GIPC_FILE, O_RDWR);
	if (fd0 < 0) {
		printf ("[server] Fd is %d %d\n", fd0, errno); 
		return -1;
	}

	/* Create a new queue on the link, get the token*/
	token0 = ioctl(fd0, GIPC_CREATE, 0);
	if (token0 < 0) {
		printf ("[server] Failed to create a new token %ld\n", token0);
		return -1;
	}

	fd1 = open (GIPC_FILE, O_RDWR);
	if (fd1 < 0) {
		printf ("[server] Fd is %d %d\n", fd1, errno);
		return -1;
	}

	// parent writes the token to the pipe
	snprintf(pidbuf, MAX_PIDBUF, "%ld", token0);
	write(p0[1], &token0, sizeof(token0));
	// Tell the client whether it is 0 or 1
	write(p0[1], &order, sizeof(order));

	/* Create a new queue on the link, get the token*/
	token1 = ioctl(fd1, GIPC_CREATE, 0);
	if (token1 < 0) {
		printf ("[server] Failed to create a new token %ld\n", token0);
		return -1;
	}

	// parent writes the token to the pipe
	write(p1[1], &token1, sizeof(token1));
	// Tell the client whether it is 0 or 1
	order++;
	write(p1[1], &order, sizeof(order));
	
	/* Send the pages to client 1 */
	gs.entries = 3;
	gs.addr = addr;
	gs.len = len;
	rv = ioctl(fd0, GIPC_SEND, &gs);
	if (rv != 3)
		printf ("[server] Bad rv %d %d (1)\n", rv, errno);

	/* Send the pages to client 2 */
	addr[0] += PAGE_SIZE *3;
	addr[1] += PAGE_SIZE *3;
	addr[2] += PAGE_SIZE *3;

	rv = ioctl(fd1, GIPC_SEND, &gs);
	if (rv != 3)
		printf ("[server] Bad rv %d (2)\n", errno);

	/* Print the value */
	x = (int *) addr[0];
	*x = 384;
	printf("[server] X contains %d\n", *x);
	x += PAGE_SIZE / sizeof(int);
	printf("[server] X contains %d\n", *x);
	x += PAGE_SIZE / sizeof(int);
	printf("[server] X contains %d\n", *x);

	wait();
	wait();

	close(fd0);
	close(fd1);

	return 0;
}
