#ifndef _DUMMY_H
#define _DUMMY_H

#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#define DUMMY_FILE	"/dev/dummy"
#define DUMMY_MINOR	MISC_DYNAMIC_MINOR

#define DUMMY_IOCTL_PRINT	_IOR('p', 0x01, struct dummy_print)

struct dummy_print {
	const char *  str;
	unsigned long size;
};

#endif /* _DUMMY_H */
