#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define BUF_SIZE 512

int main() {
    int rv, fd, offs;
    const mode_t perm = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
    char buf[BUF_SIZE];

    // setup
    // We test a directory one level below root so ".." is also present in SGX.
    rv = mkdir("root", perm);
    if (rv) {
        perror("mkdir 1");
        return 1;
    }
    rv = mkdir("root/testdir", perm);
    if (rv) {
        perror("mkdir 2");
        return 1;
    }
    rv = creat("root/testdir/file1", perm);
    if (rv < 0) {
        perror("creat 1");
        return 1;
    }
    rv = close(rv);
    if (rv) {
        perror("close 1");
        return 1;
    }
    rv = creat("root/testdir/file2", perm);
    if (rv < 0) {
        perror("creat 2");
        return 1;
    }
    rv = close(rv);
    if (rv) {
        perror("close 2");
        return 1;
    }
    rv = mkdir("root/testdir/dir3", perm);
    if (rv) {
        perror("mkdir 3");
        return 1;
    }
    // enable symlink when implemented, or just use the LTP test
    // rv = symlink("root/testdir/file2", "root/testdir/link4");
    // if (rv) { perror ("symlink"); return 1; }
    printf("getdents: setup ok\n");

    // 32-bit listing
    fd = open("root/testdir", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open 1");
        return 1;
    }

    while (1) {
        int count = syscall(SYS_getdents, fd, buf, BUF_SIZE);
        if (count < 0) {
            perror("getdents32");
            return 1;
        }
        if (count == 0)
            break;
        for (offs = 0; offs < count;) {
            struct linux_dirent* d32 = (struct linux_dirent*)(buf + offs);
            char d_type              = *(buf + offs + d32->d_reclen - 1);
            printf("getdents32: %s [0x%x]\n", d32->d_name, d_type);
            offs += d32->d_reclen;
        }
    }
    rv = close(fd);
    if (rv) {
        perror("close 1");
        return 1;
    }

    // 64-bit listing
    fd = open("root/testdir", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        perror("open 2");
        return 1;
    }

    while (1) {
        int count = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
        if (count < 0) {
            perror("getdents64");
            return 1;
        }
        if (count == 0)
            break;
        for (offs = 0; offs < count;) {
            struct linux_dirent64* d64 = (struct linux_dirent64*)(buf + offs);
            printf("getdents64: %s [0x%x]\n", d64->d_name, d64->d_type);
            offs += d64->d_reclen;
        }
    }
    rv = close(fd);
    if (rv) {
        perror("close 2");
        return 1;
    }

    // cleanup
    remove("root/testdir/file1");
    remove("root/testdir/file2");
    remove("root/testdir/dir3");
    remove("root/testdir");
    remove("root");
    return 0;
}
