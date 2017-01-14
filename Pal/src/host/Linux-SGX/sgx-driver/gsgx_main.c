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
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <asm/tlbflush.h>
#include "gsgx.h"

#define DRV_DESCRIPTION "Graphene SGX Driver"
#define DRV_VERSION "0.10"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Chia-Che Tsai <chia-che.tsai@intel.com>");
MODULE_VERSION(DRV_VERSION);

IMPORT_KSYM(dac_mmap_min_addr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
static void __enable_fsgsbase(void *v)
{
	write_cr4(read_cr4() | X86_CR4_FSGSBASE);
}
#endif

static long gsgx_ioctl_enclave_create(struct file *filep, unsigned int cmd,
				      unsigned long arg)
{
	struct gsgx_enclave_create *createp = (struct gsgx_enclave_create *) arg;
	struct sgx_enclave_create isgx_create;
	unsigned long old_mmap_min_addr = *KSYM(dac_mmap_min_addr);
	int ret;

	if (createp->src != GSGX_ENCLAVE_CREATE_NO_ADDR &&
	    createp->src < old_mmap_min_addr) {
		*KSYM(dac_mmap_min_addr) = createp->src;
		old_mmap_min_addr = 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	__enable_fsgsbase(NULL);
	smp_call_function(__enable_fsgsbase, NULL, 1);
#endif

	isgx_create.src = createp->src;
	filep->private_data = (void *) createp->src;

	ret = KSYM(isgx_ioctl_enclave_create)(filep, SGX_IOC_ENCLAVE_CREATE,
					      (unsigned long) &isgx_create);

	if (old_mmap_min_addr)
		*KSYM(dac_mmap_min_addr) = old_mmap_min_addr;
	return ret;
}

static long gsgx_ioctl_enclave_add_pages(struct file *filep, unsigned int cmd,
					 unsigned long arg)
{
	struct gsgx_enclave_add_pages *addp = (struct gsgx_enclave_add_pages *) arg;
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

static long gsgx_ioctl_enclave_init(struct file *filep, unsigned int cmd,
				    unsigned long arg)
{
	struct gsgx_enclave_init *initp = (struct gsgx_enclave_init *) arg;
	struct sgx_enclave_init isgx_init;

	isgx_init.addr = initp->addr;
	isgx_init.sigstruct = initp->sigstruct;
	isgx_init.einittoken = initp->einittoken;

	return KSYM(isgx_ioctl_enclave_init)(filep, SGX_IOC_ENCLAVE_INIT,
					     (unsigned long) &isgx_init);
}

typedef long (*ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);

long gsgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	ioctl_t handler = NULL;
	long ret;

	switch (cmd) {
		case GSGX_IOCTL_ENCLAVE_CREATE:
			handler = gsgx_ioctl_enclave_create;
			break;
		case GSGX_IOCTL_ENCLAVE_ADD_PAGES:
			handler = gsgx_ioctl_enclave_add_pages;
			break;
		case GSGX_IOCTL_ENCLAVE_INIT:
			handler = gsgx_ioctl_enclave_init;
			break;
		default:
			return -EINVAL;
	}

	if (copy_from_user(data, (void __user *) arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long) ((void *) data));

	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *) arg, data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	return ret;
}

static int gsgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	return KSYM(isgx_mmap)(file, vma);
}

static unsigned long gsgx_get_unmapped_area(struct file *file,
					    unsigned long addr,
					    unsigned long len,
					    unsigned long pgoff,
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

static const struct file_operations gsgx_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= gsgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= gsgx_ioctl,
#endif
	.mmap		= gsgx_mmap,
	.get_unmapped_area = gsgx_get_unmapped_area,
};

static struct miscdevice gsgx_dev = {
	.minor	= GSGX_MINOR,
	.name	= "gsgx",
	.fops	= &gsgx_fops,
	.mode	= S_IRUGO | S_IWUGO,
};

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

static int gsgx_lookup_ksyms(void)
{
	int ret;
	if ((ret = LOOKUP_KSYM(dac_mmap_min_addr)))
		return ret;
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

struct file *isgx_dev;

static int gsgx_setup(void)
{
	unsigned cpu;
	int ret;

	isgx_dev = filp_open("/dev/isgx", O_RDONLY, 0);
	if (!isgx_dev) {
		return PTR_ERR(isgx_dev);
	}

	ret = misc_register(&gsgx_dev);
	if (ret) {
		pr_err("gsgx: misc_register() failed\n");
		gsgx_dev.this_device = NULL;
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	for_each_online_cpu(cpu) {
		per_cpu(cpu_tlbstate.cr4, cpu) |= X86_CR4_FSGSBASE;
	}
#endif

	return 0;
}

static void gsgx_teardown(void)
{
	if (gsgx_dev.this_device)
		misc_deregister(&gsgx_dev);

	if (isgx_dev)
		filp_close(isgx_dev, NULL);
}

static int __init gsgx_init(void)
{
	int ret;

	pr_info("gsgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	ret = gsgx_lookup_ksyms();
	if (ret) {
		pr_err("Likely module \"isgx\" is not loaded\n");
		return ret;
	}

	ret = gsgx_setup();
	if (ret) {
		pr_err("Likely module \"isgx\" is not loaded\n");
		gsgx_teardown();
		return ret;
	}

	return 0;
}

static void __exit gsgx_exit(void)
{
	gsgx_teardown();
}

module_init(gsgx_init);
module_exit(gsgx_exit);
MODULE_LICENSE("GPL");
