#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* This is supposed to expose resource leaks where close()d files are not
   properly cleaned up. */

int main(int argc, char** argv) {

    for (int i = 0; i < 10000; ++i) {
        int fd = open("tmp/fdleak.c", O_RDONLY);
        assert(fd != -1);
        char buf[1024];
        int ret = read(fd, buf, sizeof(buf));
        assert(ret != -1);
        ret = close(fd);
        assert(ret != -1);
    }

    puts("Test succeeded.");
    
    return 0;
}
