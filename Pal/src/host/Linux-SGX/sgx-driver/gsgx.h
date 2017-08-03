/*
 * (C) Copyright 2013 Intel Corporation
 * Author: Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef __ARCH_GSGX_H__
#define __ARCH_GSGX_H__

#include "isgx_version.h"
#include "graphene-sgx.h"

#if SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0)

#include "isgx_ksyms.h"

extern struct file *isgx_dev;

extern long gsgx_ioctl(struct file *, unsigned int, unsigned long);
extern int gsgx_mmap(struct file *, struct vm_area_struct *);
extern unsigned long gsgx_get_unmapped_area(struct file *, unsigned long,
					    unsigned long, unsigned long,
					    unsigned long);

extern int gsgx_lookup_ksyms(void);

#endif

extern int gsgx_open(struct inode *, struct file *);

#endif /* __ARCH_GSGX_H__ */
