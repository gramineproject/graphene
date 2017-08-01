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

#include <sgx.h>
#include <sgx_arch.h>
#include <sgx_user.h>

#include "graphene-sgx.h"
#include "isgx_ksyms.h"

extern struct vm_operations_struct gsgx_vm_ops;

long gsgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);

#endif /* __ARCH_X86_GSGX_H__ */
