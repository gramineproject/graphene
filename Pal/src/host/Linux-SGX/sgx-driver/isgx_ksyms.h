#ifndef _ISGX_KSYMS_H
#define _ISGX_KSYMS_H

#include "ksyms.h"

extern IMPORT_KSYM_PROTO(sgx_ioc_enclave_create, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
extern IMPORT_KSYM_PROTO(sgx_ioc_enclave_init, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
extern IMPORT_KSYM_PROTO(sgx_ioc_enclave_add_page, long,
	struct file *filep, unsigned int cmd, unsigned long arg);

extern IMPORT_KSYM(sgx_encl_release);
extern IMPORT_KSYM_PROTO(sgx_mmap, int,
	struct file *, struct vm_area_struct *);
extern IMPORT_KSYM_PROTO(sgx_get_unmapped_area, unsigned long,
	struct file *, unsigned long, unsigned long,
	unsigned long, unsigned long);

#endif
