#ifndef _LINUX_UTILS_H
#define _LINUX_UTILS_H

#include <linux/time.h>
#include <linux/un.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

char* get_main_exec_path(void);

/* Usable only for blocking FDs */
int read_all(int fd, void* buf, size_t size);
int write_all(int fd, const void* buf, size_t size);

int read_text_file_to_cstr(const char* path, char** out);

/* Returns current time + `addend_ns` nanoseconds in `ts`. */
void time_get_now_plus_ns(struct timespec* ts, uint64_t addend_ns);
/* Returns time difference (in nanoseconds) between current time and `ts`. Note that the difference
 * can be negative! */
int64_t time_ns_diff_from_now(struct timespec* ts);

int get_graphene_unix_socket_addr(uint64_t instance_id, const char* name,
                                  struct sockaddr_un* out_addr);

#endif // _LINUX_UTILS_H
