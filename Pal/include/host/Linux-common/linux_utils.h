#ifndef _LINUX_UTILS_H
#define _LINUX_UTILS_H

#include <stddef.h>
#include <stdnoreturn.h>

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

char* get_main_exec_path(void);

/* Usable only for blocking FDs */
int read_all(int fd, void* buf, size_t size);
int write_all(int fd, const void* buf, size_t size);

int read_text_file_to_cstr(const char* path, char** out);

/* called only from GCC-emitted code; declare here to suppress GCC warn "no previous prototype" */
noreturn void __stack_chk_fail(void);

#endif // _LINUX_UTILS_H

