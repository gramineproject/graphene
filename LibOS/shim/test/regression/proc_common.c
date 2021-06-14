#define _DEFAULT_SOURCE /* lstat */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int dump(const char* path);

static int dump_dir(const char* path) {
    printf("%s: directory\n", path);
    fflush(stdout);

    char buf[4096];
    size_t path_len = strlen(path);
    if (path_len + 1 >= sizeof(buf)) {
        fprintf(stderr, "path too long: %s\n", path);
        return -1;
    }
    memcpy(buf, path, path_len);
    buf[path_len] = '/';

    int ret, close_ret;

    DIR* dir = opendir(path);
    if (!dir) {
        perror("opendir");
        ret = -1;
        goto out;
    }

    for (;;) {
        errno = 0;
        struct dirent* dirent = readdir(dir);
        if (!dirent) {
            if (errno) {
                perror("readdir");
                ret = -1;
                goto out;
            }
            break;
        }

        if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
            continue;

        size_t name_len = strlen(dirent->d_name);
        if (path_len + 1 + name_len + 1 >= sizeof(buf)) {
            fprintf(stderr, "path too long: %s/%s", path, dirent->d_name);
            ret = -1;
            goto out;
        }
        memcpy(&buf[path_len + 1], dirent->d_name, name_len + 1);
        ret = dump(buf);
        if (ret < 0)
            goto out;
    }

    ret = 0;
out:
    close_ret = closedir(dir);
    if (close_ret < 0)
        perror("closedir");
    return ret;
}

static int dump_file(const char* path) {
    printf("%s: file\n", path);
    fflush(stdout);

    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }

    char buf[4096];
    size_t n;
    int ret, close_ret;

    printf("%s: ", path);

    do {
        n = fread(buf, 1, sizeof(buf), f);
        if (ferror(f) < 0) {
            perror("fread");
            goto out;
        }

        for (size_t i = 0; i < n; i++) {
            printf("%c", buf[i]);
            if (buf[i] == '\n') {
                fflush(stdout);
                printf("%s: ", path);
            }
        }
    } while (n > 0);

    printf("\n");
    fflush(stdout);
    ret = 0;
out:
    close_ret = fclose(f);
    if (close_ret < 0)
        perror("fclose");
    return ret;
}


static int dump(const char* path) {
    int ret;
    struct stat statbuf;

    ret = lstat(path, &statbuf);
    if (ret < 0) {
        perror("lstat");
        return -1;
    }

    switch (statbuf.st_mode & S_IFMT) {
        case S_IFBLK:
            printf("%s: block device\n", path);
            fflush(stdout);
            break;
        case S_IFCHR:
            printf("%s: character device\n", path);
            break;
        case S_IFDIR:
            ret = dump_dir(path);
            if (ret < 0)
                return -1;
            break;
        case S_IFLNK: {
            char buf[4096];
            ssize_t n = readlink(path, buf, sizeof(buf));
            if (n < 0) {
                perror("readlink");
                return -1;
            }
            printf("%s: link: %.*s\n", path, (int) n, buf);
            fflush(stdout);
            break;
        }
        case S_IFREG: {
            ret = dump_file(path);
            if (ret < 0)
                return -1;
            break;
        }
        case S_IFSOCK:
            printf("%s: socket\n", path);
            fflush(stdout);
            break;
        default:
            fprintf(stderr, "unknown file type: %s\n", path);
            return -1;
    }
    return 0;
}


static void* fn(void* arg) {
    /* not to consume CPU, each thread simply sleeps */
    sleep(10000);
    return NULL;
}

int main(int argc, char** argv) {
    int ret;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* create three threads so we have some info in /proc/[pid]/task/[tid] */
        pthread_t thread[3];
        for (int j = 0; j < 3; j++) {
            ret = pthread_create(&thread[j], NULL, fn, NULL);
            if (ret < 0) {
                perror("pthread_create");
                return 1;
            }
        }

        if (dump("/proc") < 0)
            return 1;

        return 0;
    }

    /* parent process: wait for child to finish */
    int status;
    ret = waitpid(pid, &status, 0);
    if (ret < 0) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "waitpid: got %d\n", status);
        return 1;
    }
    return 0;
}
