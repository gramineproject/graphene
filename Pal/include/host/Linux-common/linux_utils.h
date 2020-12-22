#ifndef _LINUX_UTILS_H
#define _LINUX_UTILS_H

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

char* get_main_exec_path(void);

int read_text_file_to_cstr(const char* path, char** out);

/* called only from GCC-emitted code; declare here to suppress GCC warn "no previous prototype" */
noreturn void __stack_chk_fail(void);

#endif // _LINUX_UTILS_H

