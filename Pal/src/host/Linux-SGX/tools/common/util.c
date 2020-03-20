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

#include <stdlib.h>
#include <sys/stat.h>
#include "util.h"

/*! Console stdout fd */
int g_stdout_fd = 1;

/*! Console stderr fd */
int g_stderr_fd = 2;

/*! Verbosity level */
bool g_verbose = false;

void set_verbose(bool verbose) {
    g_verbose = verbose;
    if (verbose)
        DBG("Verbose output enabled\n");
    else
        DBG("Verbose output disabled\n");
}

bool get_verbose() {
    return g_verbose;
}

/* return -1 on error */
ssize_t get_file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0)
        return -1;

    return st.st_size;
}

/* Read whole file, caller should free the buffer */
uint8_t* read_file(const char* path, ssize_t* size) {
    FILE* f = NULL;
    uint8_t* buf = NULL;

    f = fopen(path, "rb");
    if (!f) {
        ERROR("Failed to open file '%s' for reading: %s\n", path, strerror(errno));
        goto out;
    }

    *size = get_file_size(fileno(f));
    if (*size == -1) {
        ERROR("Failed to get size of file '%s': %s\n", path, strerror(errno));
        goto out;
    }

    buf = (uint8_t*)malloc(*size);
    if (!buf) {
        ERROR("No memory\n");
        goto out;
    }

    if (fread(buf, *size, 1, f) != 1) {
        ERROR("Failed to read file '%s'\n", path);
        free(buf);
        buf = NULL;
    }

out:
    if (f)
        fclose(f);

    return buf;
}

static int write_file_internal(const char* path, size_t size, const void* buffer, bool append) {
    FILE* f = NULL;
    int status;

    if (append)
        f = fopen(path, "ab");
    else
        f = fopen(path, "wb");

    if (!f) {
        ERROR("Failed to open file '%s' for writing: %s\n", path, strerror(errno));
        goto out;
    }

    if (size > 0 && buffer) {
        if (fwrite(buffer, size, 1, f) != 1) {
            ERROR("Failed to write file '%s': %s\n", path, strerror(errno));
            goto out;
        }
    }

    errno = 0;

out:
    status = errno;
    if (f)
        fclose(f);
    return status;
}

/* Write buffer to file */
int write_file(const char* path, size_t size, const void* buffer) {
    return write_file_internal(path, size, buffer, false);
}

/* Append buffer to file */
int append_file(const char* path, size_t size, const void* buffer) {
    return write_file_internal(path, size, buffer, true);
}

/* Set stdout/stderr descriptors */
void util_set_fd(int stdout_fd, int stderr_fd) {
    g_stdout_fd = stdout_fd;
    g_stderr_fd = stderr_fd;
}

/* Print memory as hex */
void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;

    for (size_t i = 0; i < size; i++)
        INFO("%02x", ptr[i]);
    INFO("\n");
}
