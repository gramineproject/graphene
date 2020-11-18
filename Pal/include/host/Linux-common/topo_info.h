#ifndef _TOPO_INFO_H
#define _TOPO_INFO_H

#include "pal.h"

int get_hw_resource(const char* filename, bool count);
int read_file_buffer(const char* filename, char* buf, size_t count);
int get_core_topo_info(PAL_TOPO_INFO* topo_info);
int get_numa_topo_info(PAL_TOPO_INFO* topo_info);

#endif // _TOPO_INFO_H
