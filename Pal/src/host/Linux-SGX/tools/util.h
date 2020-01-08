/* Copyright (C) 2018-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef UTIL_H
#define UTIL_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* Miscellaneous helper functions */

extern int g_stdout_fd;
extern int g_stderr_fd;
extern bool g_verbose;

/* Print functions */
#define DBG(fmt, ...)   do { if (g_verbose) dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); } while (0)
#define INFO(fmt, ...)  do { dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); } while (0)
#define ERROR(fmt, ...) do { dprintf(g_stderr_fd, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__); } while (0)

/*! Set verbosity level */
void set_verbose(bool verbose);

/*! Get verbosity level */
bool get_verbose();

/*! Set stdout/stderr descriptors */
void util_set_fd(int stdout_fd, int stderr_fd);

/*! Get file size, return -1 on error */
ssize_t get_file_size(int fd);

/*! Read whole file, caller should free the buffer */
uint8_t* read_file(const char* path, ssize_t* size);

/*! Read size bytes from the file */
int read_file_part(const char* path, uint8_t* buffer, size_t size);

/*! Write buffer to file */
int write_file(const char* path, size_t size, const void* buffer);

/*! Append buffer to file */
int append_file(const char* path, size_t size, const void* buffer);

/*! Print memory as hex */
void hexdump_mem(void* data, size_t size);

#define HEXDUMP(x) hexdump_mem((void*)&(x), sizeof(x))

/*! Fill memory buffer with zeros */
void zero_memory(void* buffer, size_t size);

#endif
