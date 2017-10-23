/*
 * (C) Copyright 2015 Intel Corporation
 * Author: Chia-Che Tsai <chiache-che.tsai@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "gsgx.h"

#define DRV_DESCRIPTION "Graphene SGX Driver"
#define DRV_VERSION "0.10-" SDK_DRIVER_VERSION_STRING

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Chia-Che Tsai <chia-che.tsai@intel.com>");
MODULE_VERSION(DRV_VERSION);

static const struct file_operations gsgx_fops = {
	.owner		= THIS_MODULE,
	.open		= gsgx_open,

#if SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0)
	.unlocked_ioctl	= gsgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= gsgx_ioctl,
#endif
	.mmap		= gsgx_mmap,
	.get_unmapped_area = gsgx_get_unmapped_area,
#endif
};

static struct miscdevice gsgx_dev = {
	.minor	= GSGX_MINOR,
	.name	= "gsgx",
	.fops	= &gsgx_fops,
	.mode	= S_IRUGO | S_IWUGO,
};

static int gsgx_setup(void)
{
	int ret;

	ret = misc_register(&gsgx_dev);
	if (ret) {
		pr_err("gsgx: misc_register() failed\n");
		gsgx_dev.this_device = NULL;
		return ret;
	}

#if SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0)
	isgx_dev = filp_open("/dev/isgx", O_RDONLY, 0);
	if (!isgx_dev) {
		return PTR_ERR(isgx_dev);
	}

	ret = gsgx_lookup_ksyms();
	if (ret) {
		pr_err("gsgx: lookup kernel symbols failed\n");
		return ret;
	}
#endif

	return 0;
}

static void gsgx_teardown(void)
{
	if (gsgx_dev.this_device)
		misc_deregister(&gsgx_dev);

#if SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0)
	if (isgx_dev)
		filp_close(isgx_dev, NULL);
#endif
}

static int __init gsgx_init(void)
{
	int ret;

	pr_info("gsgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	ret = gsgx_setup();
	if (ret) {
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
