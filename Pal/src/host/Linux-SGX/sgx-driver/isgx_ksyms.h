#ifndef _ISGX_KSYMS_H
#define _ISGX_KSYMS_H

#include "ksyms.h"

extern IMPORT_KSYM_PROTO(isgx_ioctl_enclave_create, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
extern IMPORT_KSYM_PROTO(isgx_ioctl_enclave_init, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
extern IMPORT_KSYM_PROTO(isgx_ioctl_enclave_add_page, long,
	struct file *filep, unsigned int cmd, unsigned long arg);

extern IMPORT_KSYM(isgx_enclave_release);
extern IMPORT_KSYM_PROTO(isgx_mmap, int,
	struct file *, struct vm_area_struct *);
extern IMPORT_KSYM_PROTO(isgx_get_unmapped_area, unsigned long,
	struct file *, unsigned long, unsigned long,
	unsigned long, unsigned long);

#endif
