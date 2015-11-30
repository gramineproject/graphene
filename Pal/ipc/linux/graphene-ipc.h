#ifndef _GRAPHENE_IPC_H
#define _GRAPHENE_IPC_H

#include <linux/ioctl.h>

#define GIPC_FILE   "/dev/gipc"
#define GIPC_MINOR		240

/* Ioctl codes */
#define GIPC_SEND   _IOW('k', 0, void *)
#define GIPC_RECV   _IOR('k', 1, void *)
#define GIPC_CREATE _IOR('k', 2, void *)
#define GIPC_JOIN   _IOR('k', 3, void *)

// Must be a power of 2!
#define PAGE_QUEUE 2048
#define PAGE_BITS (PAGE_QUEUE / sizeof(unsigned long))

#define PAGE_PRESENT 1

/* Argument Structures */
typedef struct gipc_send {
	unsigned long entries;
	unsigned long *addr;
	unsigned long *len;
} gipc_send;

typedef struct gipc_recv {
	unsigned long entries;
	unsigned long *addr;
	unsigned long *len;
	unsigned long *prot;
} gipc_recv;

#endif // _GRAPHENE_IPC_H
