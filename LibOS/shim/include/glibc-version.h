/* update the file whenever changes made to glibc.
   pick whatever random value. */

#define GLIBC_VERSION 20170114

int register_library(const char* name, unsigned long load_address);
