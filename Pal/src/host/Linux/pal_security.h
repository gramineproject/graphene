/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include <linux/limits.h>

#include "pal.h"
#include "sysdeps/generic/ldsodefs.h"

extern struct pal_sec {
    /* system variables */
    int random_device;
} g_pal_sec;

#define RANDGEN_DEVICE "/dev/urandom"

#endif /* PAL_SECURITY_H */
