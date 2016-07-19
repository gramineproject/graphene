#ifndef _X86_GSGX_USER_H
#define _X86_GSGX_USER_H

#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define GSGX_FILE	"/dev/gsgx"
#define GSGX_MINOR	MISC_DYNAMIC_MINOR

#define GSGX_IOCTL_ENCLAVE_CREATE	_IOWR('p', 0x01, struct gsgx_enclave_create)
#define GSGX_IOCTL_ENCLAVE_ADD_PAGES	_IOW('p',  0x02, struct gsgx_enclave_add_pages)
#define GSGX_IOCTL_ENCLAVE_INIT		_IOW('p',  0x03, struct gsgx_enclave_init)
#define GSGX_IOCTL_ENCLAVE_DESTROY	_IOW('p',  0x04, struct gsgx_enclave_destroy)

#define GSGX_ENCLAVE_CREATE_NO_ADDR	((unsigned long) -1)

struct gsgx_enclave_create {
	void *secs;
	unsigned long addr;
};

#define GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND	0x1
#define GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC	0x2

struct gsgx_enclave_add_pages {
	unsigned int flags;
	unsigned long addr;
	unsigned long user_addr;
	unsigned long size;
	void *secinfo;
};

struct gsgx_enclave_init {
	unsigned long addr;
	void *sigstruct;
	void *einittoken;
};

struct gsgx_enclave_destroy {
	unsigned long addr;
};

#endif /* _X86_GSGX_USER_H */
