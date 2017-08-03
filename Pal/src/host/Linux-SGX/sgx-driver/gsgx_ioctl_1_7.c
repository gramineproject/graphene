/*
 * (C) Copyright 2013 Intel Corporation
 * Author: Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <asm/tlbflush.h>

#include "gsgx.h"

#if SDK_DRIVER_VERSION == KERNEL_VERSION(1, 7, 0)

struct file *isgx_dev;

static long enclave_create(struct file *filep, void * arg)
{
	struct gsgx_enclave_create *createp = arg;
	struct sgx_enclave_create isgx_create;

	isgx_create.src = createp->src;
	filep->private_data = (void *) createp->src;

	return KSYM(isgx_ioctl_enclave_create)(filep, SGX_IOC_ENCLAVE_CREATE,
					       (unsigned long) &isgx_create);
}

static long enclave_add_pages(struct file *filep, void * arg)
{
	struct gsgx_enclave_add_pages *addp = arg;
	struct sgx_enclave_add_page isgx_add;
	uint64_t off;
	int ret = 0;

	if (!addp->addr || (addp->addr & (PAGE_SIZE - 1)))
		return -EINVAL;
	if (!addp->size || (addp->size & (PAGE_SIZE - 1)))
		return -EINVAL;
	if (!addp->secinfo)
		return -EINVAL;

	isgx_add.secinfo = addp->secinfo;

	for (off = 0 ; off < addp->size ; off += PAGE_SIZE) {
		isgx_add.addr = addp->addr + off;
		isgx_add.src =
			addp->flags & GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC ?
			addp->user_addr : addp->user_addr + off;
		isgx_add.mrmask =
			addp->flags & GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND ?
 		        0 : ~0;
		ret = KSYM(isgx_ioctl_enclave_add_page)(filep,
			SGX_IOC_ENCLAVE_ADD_PAGE, (unsigned long) &isgx_add);
		if (ret < 0)
			break;
	}

	return ret;
}

static long enclave_init(struct file *filep, void * arg)
{
	struct gsgx_enclave_init *initp = arg;
	struct sgx_enclave_init isgx_init;

	isgx_init.addr = initp->addr;
	isgx_init.sigstruct = initp->sigstruct;
	isgx_init.einittoken = initp->einittoken;

	return KSYM(isgx_ioctl_enclave_init)(filep, SGX_IOC_ENCLAVE_INIT,
					     (unsigned long) &isgx_init);
}

long gsgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	long (*handler) (struct file *filp, void *arg) = NULL;
	long ret;

	switch (cmd) {
		case GSGX_IOCTL_ENCLAVE_CREATE:
			handler = enclave_create;
			break;
		case GSGX_IOCTL_ENCLAVE_ADD_PAGES:
			handler = enclave_add_pages;
			break;
		case GSGX_IOCTL_ENCLAVE_INIT:
			handler = enclave_init;
			break;
		default:
			return -EINVAL;
	}

	if (copy_from_user(data, (void __user *) arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, (void *) data);

	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *) arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	return ret;
}

int gsgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	return KSYM(isgx_mmap)(file, vma);
}

unsigned long gsgx_get_unmapped_area(struct file *file, unsigned long addr,
				     unsigned long len, unsigned long pgoff,
				     unsigned long flags)
{
	if (file->private_data == (void *) GSGX_ENCLAVE_CREATE_NO_ADDR) {
		unsigned long unmapped_addr =
			KSYM(isgx_get_unmapped_area)(file, addr, len,
						     pgoff, flags);
		file->private_data = (void *) unmapped_addr;
		return unmapped_addr;
	} else {
		unsigned long unmapped_addr = (unsigned long) file->private_data;
		struct mm_struct *mm = current->mm;
		struct vm_area_struct *vma = find_vma(mm, unmapped_addr);
		if (vma && vma->vm_start <= len)
			return -EINVAL;
		return unmapped_addr;
	}
}

IMPORT_KSYM_PROTO(isgx_ioctl_enclave_create, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
IMPORT_KSYM_PROTO(isgx_ioctl_enclave_init, long,
	struct file *filep, unsigned int cmd, unsigned long arg);
IMPORT_KSYM_PROTO(isgx_ioctl_enclave_add_page, long,
	struct file *filep, unsigned int cmd, unsigned long arg);

IMPORT_KSYM(isgx_enclave_release);
IMPORT_KSYM_PROTO(isgx_mmap, int, struct file *, struct vm_area_struct *);
IMPORT_KSYM_PROTO(isgx_get_unmapped_area, unsigned long,
	struct file *, unsigned long, unsigned long,
	unsigned long, unsigned long);

int gsgx_lookup_ksyms(void)
{
	int ret;
	if ((ret = LOOKUP_KSYM(isgx_ioctl_enclave_create)))
		return ret;
	if ((ret = LOOKUP_KSYM(isgx_ioctl_enclave_init)))
		return ret;
	if ((ret = LOOKUP_KSYM(isgx_ioctl_enclave_add_page)))
		return ret;
	if ((ret = LOOKUP_KSYM(isgx_enclave_release)))
		return ret;
	if ((ret = LOOKUP_KSYM(isgx_mmap)))
		return ret;
	if ((ret = LOOKUP_KSYM(isgx_get_unmapped_area)))
		return ret;
	return 0;
}

#endif /* SGX_DRIVER_VERSION == 1.7 */
