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
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/security.h>
#include <asm/tlbflush.h>

#include "gsgx.h"

static void __enable_fsgsbase(void *v)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	write_cr4(read_cr4() | X86_CR4_FSGSBASE);
#else
	cr4_set_bits(X86_CR4_FSGSBASE);
	__write_cr4(__read_cr4() | X86_CR4_FSGSBASE);
#endif
}

int gsgx_open(struct inode *inode, struct file *file)
{
	__enable_fsgsbase(NULL);
	smp_call_function(__enable_fsgsbase, NULL, 1);
	return 0;
}
