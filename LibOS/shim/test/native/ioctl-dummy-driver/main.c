/*
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
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <asm/tlbflush.h>

#include "dummy.h"

#define DRV_DESCRIPTION "Dummy Driver"
#define DRV_VERSION "0.0"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Chia-Che Tsai <chia-che.tsai@intel.com>");
MODULE_VERSION(DRV_VERSION);

static long dummy_print(struct file *filep, void * arg)
{
	char data[256];
	struct dummy_print *printp = arg;
	if (printp->size >= 256)
		return -EINVAL;
	if (copy_from_user(data, (void __user *) printp->str, printp->size))
		return -EFAULT;
	data[printp->size] = '\0';
	printk(KERN_ERR "dummy print: %s\n", data);
	return 0;
}

long dummy_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	long (*handler) (struct file *filp, void *arg) = NULL;
	long ret;

	switch (cmd) {
		case DUMMY_IOCTL_PRINT:
			handler = dummy_print;
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

int dummy_open(struct inode *inode, struct file *file)
{
	return 0;
}

int dummy_fault(struct vm_fault *vmf)
{
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return VM_FAULT_OOM;

	vm_insert_pfn(vmf->vma, vmf->address, page_to_pfn(page));
	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct dummy_vm_ops = {
	.fault		= dummy_fault,
};

int dummy_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &dummy_vm_ops;
	vma->vm_flags |= VM_IO | VM_PFNMAP;
	return 0;
}

static const struct file_operations dummy_fops = {
	.owner		= THIS_MODULE,
	.open		= dummy_open,
	.mmap		= dummy_mmap,
	.unlocked_ioctl	= dummy_ioctl,
	.compat_ioctl	= dummy_ioctl,
};

static struct miscdevice dummy_dev = {
	.minor	= DUMMY_MINOR,
	.name	= "dummy",
	.fops	= &dummy_fops,
	.mode	= S_IRUGO | S_IWUGO,
};

static int dummy_setup(void)
{
	int ret;

	ret = misc_register(&dummy_dev);
	if (ret) {
		pr_err("dummy: misc_register() failed\n");
		dummy_dev.this_device = NULL;
		return ret;
	}

	return 0;
}

static void dummy_teardown(void)
{
	if (dummy_dev.this_device)
		misc_deregister(&dummy_dev);
}

static int __init dummy_init(void)
{
	int ret;

	pr_info("dummy: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	ret = dummy_setup();
	if (ret) {
		dummy_teardown();
		return ret;
	}

	return 0;
}

static void __exit dummy_exit(void)
{
	dummy_teardown();
}

module_init(dummy_init);
module_exit(dummy_exit);
MODULE_LICENSE("GPL");
