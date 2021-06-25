/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Test for POSIX locks (`fcntl(F_SETLK/F_SETLKW/F_GETLK`). We assert that the calls succeed (or
 * taking a lock fails), and log all details for debugging purposes.
 *
 * The tests usually start another process, and coordinate with it using pipes.
 */
#define _POSIX_C_SOURCE 1 /* fileno() */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_FILE "tmp/file"

static int g_fd;
static int g_pipe[2][2];

static const char* str_cmd(int cmd) {
    switch (cmd) {
        case F_SETLK: return "F_SETLK";
        case F_SETLKW: return "F_SETLKW";
        case F_GETLK: return "F_GETLK";
        default: return "???";
    }
}

static const char* str_type(int type) {
    switch (type) {
        case F_RDLCK: return "F_RDLCK";
        case F_WRLCK: return "F_WRLCK";
        case F_UNLCK: return "F_UNLCK";
        default: return "???";
    }
}

static const char* str_whence(int whence) {
    switch (whence) {
        case SEEK_SET: return "SEEK_SET";
        case SEEK_CUR: return "SEEK_CUR";
        case SEEK_END: return "SEEK_END";
        default: return "???";
    }
}

static const char* str_err(int err) {
    switch (err) {
        case EACCES: return "EACCES";
        case EAGAIN: return "EAGAIN";
        default: return "???";
    }
}

/* Run fcntl command and log it, along with the result. Returns true if it suceeds (F_SETLK returns
 * success, F_GETLK returns no conflicting lock). */
static bool try_lock(int cmd, int type, int whence, long int start, long int len) {
    assert(cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK);
    assert(type == F_RDLCK || type == F_WRLCK || type == F_UNLCK);
    assert(whence == SEEK_SET || whence == SEEK_CUR || whence == SEEK_END);

    struct flock fl = {
        .l_type = type,
        .l_whence = whence,
        .l_start = start,
        .l_len = len,
    };
    int ret = fcntl(g_fd, cmd, &fl);
    if (ret == -1 && errno != EACCES && errno != EAGAIN)
        err(1, "fcntl");

    fprintf(stderr, "%d: fcntl(fd, %s, {%s, %s, %4ld, %4ld}) = %s", getpid(), str_cmd(cmd),
            str_type(type), str_whence(whence), start, len, ret == 0 ? "0" : str_err(errno));
    if (ret == 0 && cmd == F_GETLK) {
        if (fl.l_type == F_UNLCK) {
            fprintf(stderr, "; {%s}\n", str_type(fl.l_type));
        } else {
            fprintf(stderr, "; {%s, %s, %4ld, %4ld, %d}\n", str_type(fl.l_type),
                    str_whence(fl.l_whence), fl.l_start, fl.l_len, fl.l_pid);
        }
    } else {
        fprintf(stderr, "\n");
    }

    fflush(stderr);

    if (cmd == F_GETLK) {
        return fl.l_type == F_UNLCK;
    } else {
        return ret == 0;
    }
}

static void unlock(long int start, long int len) {
    if (!try_lock(F_SETLK, F_UNLCK, SEEK_SET, start, len))
        errx(1, "untry_lock failed");
}

static void lock_ok(int type, long int start, long int len) {
    assert(type == F_RDLCK || type == F_WRLCK);

    if (!try_lock(F_GETLK, type, SEEK_SET, start, len)
            || !try_lock(F_SETLK, type, SEEK_SET, start, len))
        errx(1, "setting %s failed", str_type(type));
}

static void lock_wait_ok(int type, long int start, long int len) {
    if (!try_lock(F_SETLKW, type, SEEK_SET, start, len))
        errx(1, "waiting for %s failed", str_type(type));
}

static void lock_fail(int type, long int start, long int len) {
    if (try_lock(F_GETLK, type, SEEK_SET, start, len)
            || try_lock(F_SETLK, type, SEEK_SET, start, len))
        errx(1, "setting %s succeeded unexpectedly", str_type(type));
}

/*
 * Test: lock/unlock various ranges. The locks are all for the same process, so the test is unlikely
 * to fail, but it's useful for checking if the locks are replaced and merged correctly (by looking
 * at Graphene debug output).
 */
static void test_ranges() {
    printf("test ranges...\n");
    unlock(0, 0);

    /* Lock some ranges, check joining adjacent ranges */
    lock_ok(F_RDLCK, 10, 10);
    lock_ok(F_RDLCK, 30, 10);
    lock_ok(F_RDLCK, 20, 10);
    lock_ok(F_RDLCK, 1000, 0);

    /* Unlock some ranges, check subtracting and splitting ranges */
    unlock(5, 10);
    unlock(20, 5);
    unlock(35, 10);
    unlock(950, 100);

    /* Overwrite with write lock */
    lock_ok(F_WRLCK, 0, 30);
    lock_ok(F_WRLCK, 30, 30);
}

static void wait_for_child(void) {
    int ret;
    do {
        ret = wait(NULL);
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "wait");
}

static void write_pipe(unsigned int i) {
    char c = 0;
    int ret;
    do {
        ret = write(g_pipe[i][1], &c, sizeof(c));
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "write");
}

static void read_pipe(unsigned int i) {
    char c;
    int ret;
    do {
        ret = read(g_pipe[i][0], &c, sizeof(c));
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "write");
    if (ret == 0)
        errx(1, "pipe closed");
}

/* Test: child takes a lock and then exits. The lock should be released. */
static void test_child_exit() {
    printf("test child exit...\n");
    unlock(0, 0);

    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");

    if (pid == 0) {
        lock_ok(F_WRLCK, 0, 100);
        write_pipe(0);
        read_pipe(1);
        exit(0);
    }

    read_pipe(0);
    lock_fail(F_RDLCK, 0, 100);
    write_pipe(1);
    lock_wait_ok(F_RDLCK, 0, 100);
    wait_for_child();
}

/* Test: child takes a lock, and then closes a duplicated FD. The lock should be released. */
static void test_file_close() {
    printf("test file close...\n");
    unlock(0, 0);

    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");

    if (pid == 0) {
        lock_ok(F_WRLCK, 0, 100);
        write_pipe(0);
        read_pipe(1);

        int fd2 = dup(g_fd);
        if (fd2 < 0)
            err(1, "fopen");

        if (close(fd2) < 0)
            err(1, "close");

        read_pipe(1);
        exit(0);
    }

    read_pipe(0);
    lock_fail(F_RDLCK, 0, 100);
    write_pipe(1);
    lock_wait_ok(F_RDLCK, 0, 100);
    write_pipe(1);
    wait_for_child();
}

/* Test: child waits for parent to release a lock. */
static void test_child_wait() {
    printf("test child wait...\n");
    unlock(0, 0);

    lock_ok(F_RDLCK, 0, 100);

    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");

    if (pid == 0) {
        lock_ok(F_RDLCK, 0, 100);
        lock_fail(F_WRLCK, 0, 100);
        write_pipe(0);
        lock_wait_ok(F_WRLCK, 0, 100);
        exit(0);
    }

    read_pipe(0);
    unlock(0, 100);

    wait_for_child();
}

/* Test: parent waits for child to release a lock. */
static void test_parent_wait() {
    printf("test parent wait...\n");
    unlock(0, 0);

    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");

    if (pid == 0) {
        lock_ok(F_RDLCK, 0, 100);
        write_pipe(0);
        read_pipe(1);
        unlock(0, 100);
        read_pipe(1);
        exit(0);
    }

    /* parent process: */

    read_pipe(0);

    /* read lock should succeed */
    lock_ok(F_RDLCK, 0, 100);
    lock_fail(F_WRLCK, 0, 100);
    write_pipe(1);
    lock_wait_ok(F_WRLCK, 0, 100);
    write_pipe(1);

    wait_for_child();
}

int main(void) {
    setbuf(stdout, NULL);

    FILE* fp = fopen(TEST_FILE, "w+");
    if (!fp)
        err(1, "fopen");

    g_fd = fileno(fp);

    for (unsigned int i = 0; i < 2; i++) {
        if (pipe(g_pipe[i]) < 0)
            err(1, "pipe");
    }

    test_ranges();
    test_child_exit();
    test_file_close();
    test_child_wait();
    test_parent_wait();

    if (fclose(fp) == EOF)
        err(1, "fclose");

    for (unsigned int i = 0; i < 2; i++) {
        if (close(g_pipe[i][0]) < 0)
            err(1, "close pipe");
        if (close(g_pipe[i][1]) < 0)
            err(1, "close pipe");
    }

    printf("TEST OK\n");
    return 0;
}
