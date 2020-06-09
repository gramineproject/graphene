/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* Miscellaneous helper functions */

/*! Order of bytes for hex strings (display and parsing) */
typedef enum _endianness_t {
    ENDIAN_LSB,
    ENDIAN_MSB,
} endianness_t;

extern int g_stdout_fd;
extern int g_stderr_fd;
extern bool g_verbose;
extern endianness_t g_endianness;

/* Print functions */
#define DBG(fmt, ...)   do { if (g_verbose) dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); } while (0)
#define INFO(fmt, ...)  do { dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); } while (0)
#define ERROR(fmt, ...) do { dprintf(g_stderr_fd, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__); } while (0)

/*! Set verbosity level */
void set_verbose(bool verbose);

/*! Get verbosity level */
bool get_verbose(void);

/*! Set endianness for hex strings */
void set_endianness(endianness_t endianness);

/*! Get endianness for hex strings */
endianness_t get_endianness(void);

/*! Set stdout/stderr descriptors */
void util_set_fd(int stdout_fd, int stderr_fd);

/*! Get file size, return -1 on error */
ssize_t get_file_size(int fd);

/*! Read whole file, caller should free the buffer */
uint8_t* read_file(const char* path, ssize_t* size);

/*! Write buffer to file */
int write_file(const char* path, size_t size, const void* buffer);

/*! Append buffer to file */
int append_file(const char* path, size_t size, const void* buffer);

/*! Print memory as hex to buffer */
int hexdump_mem_to_buffer(const void* data, size_t size, char* buffer, size_t buffer_size);

/*! Print memory as hex */
void hexdump_mem(const void* data, size_t size);

/*! Print variable as hex */
#define HEXDUMP(x) hexdump_mem((const void*)&(x), sizeof(x))

/*! Parse hex string to buffer */
int parse_hex(const char* hex, void* buffer, size_t buffer_size);

/*! abort */
void __abort(void);

/* For PAL's assert compatibility */
#ifndef warn
#define warn ERROR
#endif

#endif /* UTIL_H */
