#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "../graphene-ipc.h"
#define PAGE_SIZE 4096
#define MAX_PIDBUF 20
#define MAX_PATH 256

int main () {

	volatile int *x = NULL;
	int fd, fd1, rv;
	struct gipc_recv gr;
	struct gipc_send gs;
	pid_t other_client;
	char pidbuf[MAX_PIDBUF];	
	unsigned long len = PAGE_SIZE;
	unsigned long addr = 0;
	int64_t token;
	int order;
	unsigned long gr_addr, gr_len;
	int gr_prot;

	gr.entries = 1;
	gr.addr = &gr_addr;
	gr.len = &gr_len;
	gr.prot = &gr_prot;

	read(0, &token, sizeof(token));
	read(0, &order, sizeof(order));

	/* Open an IPC link */
	fd = open (GIPC_FILE, O_RDWR);
	if (fd < 0) {
		printf ("[client] Fd is %d %d\n", fd, errno);
		return -1;
	}

	/* Set the channel */
	rv = ioctl(fd, GIPC_JOIN, token);
	if (rv < 0) {
		printf("[client] Failed to join ipc channel - %d, %d\n", rv, errno);
		return -1;
	}

	gr_len = PAGE_SIZE * 3;
	gr_addr = 0;
	gr_prot = PROT_READ | PROT_WRITE;

	/* Recv the page */
	rv = ioctl(fd, GIPC_RECV, &gr);
	if (rv) {
		printf ("Bad map %p rv %d %d\n", (void *)gr_addr, rv, errno);
		return 1;
	}

	/* Try a memory barrier */
	asm volatile ("nop" :::"memory");

	x = (int *) gr_addr;

	/* Print the value */
	printf("[client] X contains %d, from %d\n", *x, fd);
	x += PAGE_SIZE / sizeof(int);
	printf("[client] X contains %d, from %d\n", *x, fd);
	x += PAGE_SIZE / sizeof(int);
	printf("[client] X contains %d, from %d\n", *x, fd);
	*x += 3820;

	other_client = *(int *) gr_addr;

	printf("[client] other pid is %d\n", other_client);

	/* Map an anonymous page */
	addr = (unsigned long) x;
	gs.entries = 1;
	gs.addr = &addr;
	gs.len = &len;

	/* Send the pages to other client */
	fd1 = open (GIPC_FILE, O_RDWR);
	if (!order) {
		// Create the queue
		token = ioctl(fd1, GIPC_CREATE, 0);
		if (token < 0) {
			printf ("[server] Failed to create a new token %ld\n", token);
			return -1;
		}

		// Write to token to handle 3 (write pipe)
		write(3, &token, sizeof(token));
	} else {
		// Join the queue
		rv = read(3, &token, sizeof(token));
		if (rv != sizeof(token)) {
			printf("Failed to get the token - %d\n", errno);
		}

		rv = ioctl(fd1, GIPC_JOIN, token);
		if (rv < 0) {
			printf("[client] Failed to join ipc channel - %d, %d\n", rv, errno);
			return -1;
		}
	}

	rv = ioctl(fd1, GIPC_SEND, &gs);
	if (rv != gs.entries)
		printf ("[client] Bad rv %d (%d)\n", errno, rv);

	gr_len = PAGE_SIZE;
	gr_addr = 0;
	//gr.wait_on_src = other_client;

	/* Recv the page */
	rv = ioctl(fd1, GIPC_RECV, &gr);
	if (rv) {
		printf ("Bad map %p rv %d %d\n", (void *)gr_addr, rv, errno);
		return 1;
	}

	/* Try a memory barrier */
	asm volatile ("nop" :::"memory");

	x = (int *) gr_addr;

	/* Print the value */
	printf("[client] X contains %d, from %d\n", *x, fd1);

	close(fd1);
	close(fd);


	return 0;
}
