#include "syscalldb.h"
#include <stdarg.h>

int register_library (const char * name, unsigned long load_address)
	__attribute__((weak));

int register_library (const char * name, unsigned long load_address)
{
	return 0;
}
