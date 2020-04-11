#include "common.h"

int g_mode = 0664;
char g_data = 'x';

#define OPEN_TEST(flags, exists, expect_success, do_write) {    \
    char* s = exists ? "[exists]" : "[doesn't exist]";          \
    fd = open(argv[1], flags, g_mode);                          \
    if (fd < 0) {                                               \
        if (expect_success) {                                   \
            fatal_error("open(" #flags ") %s failed!\n", s);    \
        } else {                                                \
            printf("open(" #flags ") %s failed OK\n", s);       \
        }                                                       \
    } else {                                                    \
        if (expect_success) {                                   \
            printf("open(" #flags ") %s succeeded OK\n", s);    \
            if (do_write)                                       \
                write_fd(argv[1], fd, &g_data, sizeof(g_data)); \
        } else {                                                \
            fatal_error("open(" #flags ") %s succeeded!\n", s); \
        }                                                       \
        close(fd);                                              \
    }                                                           \
}

size_t get_file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) < 0)
        fatal_error("Failed to stat file '%s': %s\n", path, strerror(errno));
    printf("size(%s) == %zu\n", path, st.st_size);
    return st.st_size;
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <path>\n", argv[0]);

    setup();
    int fd = -1;

    // doesn't exist - should create
    OPEN_TEST(O_CREAT|O_EXCL|O_RDWR, /*exists=*/false, /*expect_success=*/true, /*do_write=*/true);

    // exists - open should fail
    OPEN_TEST(O_CREAT|O_EXCL|O_RDWR, /*exists=*/true, /*expect_success=*/false, /*do_write=*/false);

    // exists - should open existing and NOT truncate
    OPEN_TEST(O_CREAT|O_RDWR, /*exists=*/true, /*expect_success=*/true, /*do_write=*/false);
    if (get_file_size(argv[1]) != 1)
        fatal_error("File was truncated\n");

    if (unlink(argv[1]) < 0)
        fatal_error("unlink(%s) failed: %s\n", argv[1], strerror(errno));

    // doesn't exist - should create new
    OPEN_TEST(O_CREAT|O_RDWR, /*exists=*/false, /*expect_success=*/true, /*do_write=*/false);

    if (unlink(argv[1]) < 0)
        fatal_error("unlink(%s) failed: %s\n", argv[1], strerror(errno));

    // doesn't exist - should create new
    OPEN_TEST(O_CREAT|O_TRUNC|O_RDWR, /*exists=*/false, /*expect_success=*/true, /*do_write=*/true);

    // exists - should truncate
    OPEN_TEST(O_CREAT|O_TRUNC|O_RDWR, /*exists=*/true, /*expect_success=*/true, /*do_write=*/false);
    if (get_file_size(argv[1]) != 0)
        fatal_error("File was not truncated\n");

    if (unlink(argv[1]) < 0)
        fatal_error("unlink(%s) failed: %s\n", argv[1], strerror(errno));

    return 0;
}
