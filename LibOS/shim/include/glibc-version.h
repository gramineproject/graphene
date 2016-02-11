/* update the file whenever changes made to glibc.
   pick whatever random value. */

#define GLIBC_VERSION_2_17      0xd893a451

int register_library (const char * name, unsigned long load_address);
