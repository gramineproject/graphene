#ifndef _LINUX_UTILS_H
#define _LINUX_UTILS_H

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

char* get_main_exec_path(void);

int read_text_file_to_cstr(const char* path, char** out);

#endif // _LINUX_UTILS_H

