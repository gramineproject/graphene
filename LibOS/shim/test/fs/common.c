#include "common.h"

__attribute__((noreturn))
void error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
    exit(-1);
}

void setup() {
    // set output to line-buffered for easier debugging
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    srand(time(0));
}

int open_input_fd(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        error("Failed to open input file %s: %s\n", path, strerror(errno));
    return fd;
}

void read_fd(const char* path, int fd, void* buffer, size_t size) {
    if (size > 0) {
        size_t ret = read(fd, buffer, size);
        if (ret != size)
            error("Failed to read file %s: %s\n", path, strerror(errno));
    }
}

void seek_fd(const char* path, int fd, size_t offset) {
    int ret = lseek(fd, offset, SEEK_SET);
    if (ret < 0)
        error("Failed to seek file %s (%zu): %s\n", path, offset, strerror(errno));
}

int open_output_fd(const char* path, bool rdwr) {
    int fd = open(path, rdwr ? O_RDWR|O_CREAT : O_WRONLY|O_CREAT, 0664);
    if (fd < 0)
        error("Failed to open output file %s: %s\n", path, strerror(errno));
    return fd;
}

void write_fd(const char* path, int fd, const void* buffer, size_t size) {
    if (size > 0) {
        size_t ret = write(fd, buffer, size);
        if (ret != size)
            error("Failed to write file %s: %s\n", path, strerror(errno));
    }
}

void close_fd(const char* path, int fd) {
    if (fd >= 0)
        if (close(fd) != 0)
            error("Failed to close file %s: %s\n", path, strerror(errno));
}

void* mmap_fd(const char* path, int fd, int protection, size_t offset, size_t size) {
    void* address = mmap(NULL, size, protection, MAP_SHARED, fd, offset);

    if (address == MAP_FAILED)
        error("Failed to mmap file %s: %s\n", path, strerror(errno));
    return address;
}

void munmap_fd(const char* path, void* address, size_t size) {
    if (munmap(address, size) < 0)
        error("Failed to munmap file %s: %s\n", path, strerror(errno));
}

FILE* open_input_stdio(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f)
        error("Failed to open input file %s: %s\n", path, strerror(errno));
    return f;
}

void read_stdio(const char* path, FILE* f, void* buffer, size_t size) {
    if (size > 0) {
        size_t ret = fread(buffer, size, 1, f);
        if (ret != 1)
            error("Failed to read file %s: %s\n", path, strerror(errno));
    }
}

void seek_stdio(const char* path, FILE* f, size_t offset) {
    if (offset > LONG_MAX)
        error("Failed to seek file %s(%zu): offset too big\n", path, offset);
    int ret = fseek(f, (long)offset, SEEK_SET);
    if (ret < 0)
        error("Failed to seek file %s(%zu): %s\n", path, offset, strerror(errno));
}

void close_stdio(const char* path, FILE* f) {
    if (f)
        if (fclose(f) != 0)
            error("Failed to close file %s: %s\n", path, strerror(errno));
}

FILE* open_output_stdio(const char* path) {
    FILE* f = fopen(path, "w");
    if (!f)
        error("Failed to open output file %s: %s\n", path, strerror(errno));
    return f;
}

void write_stdio(const char* path, FILE* f, const void* buffer, size_t size) {
    if (size > 0) {
        size_t ret = fwrite(buffer, size, 1, f);
        if (ret != 1)
            error("Failed to write file %s: %s\n", path, strerror(errno));
    }
}

void* alloc_buffer(size_t size) {
    void* buffer = malloc(size);
    if (!buffer)
        error("No memory\n");
    return buffer;
}

void fill_random(void* buffer, size_t size) {
    for (size_t i = 0; i < size; i++)
        ((uint8_t*)buffer)[i] = rand() % 256;
}
