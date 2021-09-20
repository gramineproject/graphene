/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

#ifndef TOPO_INFO_H_
#define TOPO_INFO_H_

#include "pal.h"

/* Opens a pseudo-file describing HW resources such as online CPUs and counts the number of
 * HW resources present in the file (if count == true) and stores the result in `PAL_RES_RANGE_INFO`
 * struct if provided or simply reads the integer stored in the file (if count == false). If
 * `size_mult` is passed, then numerical representation of size qualifier like "K"/"M"/"G" is
 * stored while reading the integer. For example on a single-core machine, calling this function on
 * `/sys/devices/system/cpu/online` with count == true will return 1 and 0 with count == false.
 * Returns UNIX error code on failure.
 * N.B: Understands complex formats like "1,3-5,6" when called with count == true.
 */
int get_hw_resource(const char* filename, bool count, PAL_RES_RANGE_INFO* res_info,
                    uint64_t* size_mult);

/* Reads up to count bytes from the file into the buf passed.
 * Returns 0 or number of bytes read on success and UNIX error code on failure.
 */
int read_file_buffer(const char* filename, char* buf, size_t count);
/* Fills topo_info with CPU and NUMA topology from the host */
int get_topology_info(PAL_TOPO_INFO* topo_info);

#endif // TOPO_INFO_H_
