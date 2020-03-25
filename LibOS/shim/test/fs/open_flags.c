#include "common.h"

int g_mode = 0664;

#define OPEN_TEST(flags, exists, expect_success) {                \
    char* s;                                                      \
    fd = open(argv[1], flags, g_mode);                            \
    s = exists ? "[exists]" : "[doesn't exist]";                  \
    if (fd < 0) {                                                 \
        if (expect_success) {                                     \
            printf("ERROR: open(" #flags ") %s failed!\n", s);    \
            return -1;                                            \
        } else {                                                  \
            printf("open(" #flags ") %s failed OK\n", s);         \
        }                                                         \
    } else {                                                      \
        close(fd);                                                \
        if (expect_success) {                                     \
            printf("open(" #flags ") %s succeeded OK\n", s);      \
        } else {                                                  \
            printf("ERROR: open(" #flags ") %s succeeded!\n", s); \
            return -1;                                            \
        }                                                         \
    }                                                             \
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <path>\n", argv[0]);

    setup();
    int fd = -1;

    // doesn't exist - should create
    OPEN_TEST(O_CREAT|O_EXCL|O_RDWR, /*exists=*/false, /*expect_success=*/true);

    // exists - open should fail
    OPEN_TEST(O_CREAT|O_EXCL|O_RDWR, /*exists=*/true, /*expect_success=*/false);

    // exists - should open existing
    OPEN_TEST(O_CREAT|O_RDWR, /*exists=*/true, /*expect_success=*/true);
    unlink(argv[1]);

    // doesn't exist - should create new
    OPEN_TEST(O_CREAT|O_RDWR, /*exists=*/false, /*expect_success=*/true);
    unlink(argv[1]);

    // doesn't exist - should create new
    OPEN_TEST(O_CREAT|O_TRUNC|O_RDWR, /*exists=*/false, /*expect_success=*/true);

    // exists - should truncate
    OPEN_TEST(O_CREAT|O_TRUNC|O_RDWR, /*exists=*/true, /*expect_success=*/true);
    unlink(argv[1]);

    return 0;
}
