#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int get_random_int(long maxprocs) {
    return rand() % maxprocs;
}

static void display_file_contents(const char* path) {
    char buf[4096];
    int ret;
    FILE* fd;

    printf("===== Contents of %s file =====\n", path);
    fd = fopen(path, "r");
    if (!fd)
         err(EXIT_FAILURE, "fopen failed for %s", path);

    ret = fread(buf, 1, sizeof(buf) - 1, fd);
    if (ferror(fd))
         err(EXIT_FAILURE, "fread failed for %s", path);
    buf[ret] = '\0';

    printf("%s\n", buf);

    ret = fclose(fd);
    if (ret)
        err(EXIT_FAILURE, "fclose failed for %s", path);
}

int main(int argc, char** argv) {
    char path[256];
    int ret, count = 0;
    FILE* fd;
    DIR* dir;
    struct dirent* dirent;
    struct dirent64* dirent64;
    struct stat sb;

    long maxprocs = sysconf(_SC_NPROCESSORS_CONF);
    printf("Number of processors: %ld\n", maxprocs);

    printf("===== faccessat of sys/devices/system/cpu =====\n");
    ret = faccessat(-1, "/sys/devices/system/cpu", R_OK, 0);
    if (ret)
        err(EXIT_FAILURE, "faccessat failed for /sys/devices/system/cpu");

    printf("===== fopen of sys/devices/system/node =====\n");
    fd = fopen("/sys/devices/system/node", "r");
    if (!fd)
        err(EXIT_FAILURE, "fopen failed for /sys/devices/system/cpu");

    ret = fclose(fd);
    if (ret)
        err(EXIT_FAILURE, "fclose failed for /sys/devices/system/cpu");

    /* skip this test, if it is a single-core machine */
    if (maxprocs > 0) {
        display_file_contents("/sys/devices/system/cpu/cpu1/online");
    }

    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/core_id",
             get_random_int(maxprocs));
    display_file_contents(path);

    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/topology/core_siblings",
             get_random_int(maxprocs));
    display_file_contents(path);

    display_file_contents("/sys/devices/system/node/node0/cpumap");

    display_file_contents("/sys/devices/system/node/node0/distance");

    display_file_contents("/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages");

    /* Read L1 data, L1 Instruction and L2 cache type*/
    for (int lvl = 0; lvl < 3; lvl++) {
        snprintf(path, sizeof(path),"/sys/devices/system/cpu/cpu%d/cache/index%d/type",
                 get_random_int(maxprocs), lvl);
        display_file_contents(path);
    }

    printf("===== fstatat of /sys/devices/system/node/node0/hugepages =====\n");
    ret = fstatat(-1, "/sys/devices/system/node/node0/hugepages", &sb, 0);
    if (ret)
        err(EXIT_FAILURE, "fstatat failed for /sys/devices/system/node/node0/hugepages");

    printf("ID of containing device:  [%lx,%lx]\n", (long)major(sb.st_dev), (long)minor(sb.st_dev));

    printf("File type:                ");
    switch (sb.st_mode & S_IFMT) {
        case S_IFBLK:  printf("block device\n");            break;
        case S_IFCHR:  printf("character device\n");        break;
        case S_IFDIR:  printf("directory\n");               break;
        case S_IFIFO:  printf("FIFO/pipe\n");               break;
        case S_IFLNK:  printf("symlink\n");                 break;
        case S_IFREG:  printf("regular file\n");            break;
        case S_IFSOCK: printf("socket\n");                  break;
        default:       printf("unknown?\n");                break;
    }

    printf("I-node number:            %ld\n", (long)sb.st_ino);
    printf("Mode:                     %lo (octal)\n", (unsigned long)sb.st_mode);
    printf("Link count:               %ld\n", (long) sb.st_nlink);
    printf("Ownership:                UID=%ld   GID=%ld\n", (long)sb.st_uid, (long)sb.st_gid);
    printf("Preferred I/O block size: %ld bytes\n", (long)sb.st_blksize);
    printf("File size:                %lld bytes\n", (long long)sb.st_size);
    printf("Blocks allocated:         %lld\n", (long long)sb.st_blocks);

    printf("\n===== Count num of CPUs from /sys/devices/system/cpu =====\n");
    dir = opendir("/sys/devices/system/cpu");
    if (!dir)
        err(EXIT_FAILURE, "opendir failed for /sys/devices/system/cpu");

    errno = 0;
    while ((dirent64 = readdir64(dir))) {
        printf("/sys/devices/system/cpu/%s, type=%d\n", dirent64->d_name, dirent64->d_type);
        if (dirent64->d_type == DT_DIR && strncmp (dirent64->d_name, "cpu", 3) == 0) {
            char *endp;
            unsigned long int nr = strtoul (dirent64->d_name + 3, &endp, 10);
            if (nr != _SC_ULONG_MAX && endp != dirent64->d_name + 3 && *endp == '\0')
                count++;
        }
    }

    if (errno) {
        perror("readdir /sys/devices/system/cpu");
        return 1;
    }
    printf("Total CPU count=%d\n", count);

    ret = closedir(dir);
    if (ret < 0) {
        perror("closedir /sys/devices/system/cpu");
        return 1;
    }

    printf("\n===== Count num of nodes from /sys/devices/system/node =====\n");
    count = 0;
    dir = opendir("/sys/devices/system/node");
    if (!dir)
         err(EXIT_FAILURE, "opendir failed for /sys/devices/system/node");

    errno = 0;
    while ((dirent = readdir(dir))) {
        printf("/sys/devices/system/node/%s \n", dirent->d_name);
        if (strncmp (dirent->d_name, "node", 4) == 0) {
            char *endp;
            unsigned long int nr = strtoul(dirent->d_name + 4,  &endp, 10);
            if (nr != _SC_ULONG_MAX && endp != dirent64->d_name + 4 && *endp == '\0')
                count++;
        }
    }

    if (errno) {
        perror("readdir /sys/devices/system/node");
        return 1;
    }
    printf("Total Node count=%d\n", count);

    ret = closedir(dir);
    if (ret < 0) {
        perror("closedir /sys/devices/system/node");
        return 1;
    }

    printf("TEST OK\n");
    return 0;
}
