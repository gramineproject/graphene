#ifndef TOPO_INFO_H_
#define TOPO_INFO_H_

#include "pal.h"

/* Opens a pseudo-file describing HW resources such as online CPUs and counts the number of
 * HW resources present in the file (if count == true) or simply reads the integer stored in the
 * file (if count == false). For example on a single-core machine, calling this function on
 * `/sys/devices/system/cpu/online` with count == true will return 1 and 0 with count == false.
 * Returns UNIX error code on failure.
 * N.B: Understands complex formats like "1,3-5,6" when called with count == true.
 */
int get_hw_resource(const char* filename, bool count);

/* Reads up to count bytes from the file into the buf passed.
 * Returns 0 or number of bytes read on success and UNIX error code on failure.
 */
int read_file_buffer(const char* filename, char* buf, size_t count);
int get_core_topo_info(PAL_TOPO_INFO* topo_info);
int get_numa_topo_info(PAL_TOPO_INFO* topo_info);

#endif // TOPO_INFO_H_
