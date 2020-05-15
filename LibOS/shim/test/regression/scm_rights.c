#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define UNIX_SOCKET_NAME "dummy_unix_socket"

#define VLEN 5
#define BUFSIZE 100

#define STR_ONE   "one"
#define STR_TWO   "two"
#define STR_THREE "three"
#define STR_HELLO "hello world"

/* ancillary data buffer, wrapped in a union in order to ensure it is suitably aligned */
union {
    char buf[CMSG_SPACE(sizeof(int)) * 2];  /* want to send two cmsg */
    struct cmsghdr align;
} cmsghdr_union;

/* pipe to be transmitted from parent process to child via SCM_RIGHTS */
int pipefds[2] = {-1, -1};

int server(void) {
    int ret;

    ret = pipe(pipefds);
    if (ret < 0) {
        perror("[parent] pipe error");
        exit(1);
    }

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[parent] socket error");
        exit(1);
    }

    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, UNIX_SOCKET_NAME, sizeof(address.sun_path));

    ret = bind(listen_fd, (struct sockaddr*)&address, sizeof(address));
    if (ret < 0) {
        close(listen_fd);
        perror("[parent] bind error");
        exit(1);
    }

    ret = listen(listen_fd, 3);
    if (ret < 0) {
        close(listen_fd);
        perror("[parent] listen error");
        exit(1);
    }

    socklen_t addrlen = sizeof(address);

    int fd = accept(listen_fd, (struct sockaddr*)&address, &addrlen);
    if (fd < 0) {
        close(listen_fd);
        perror("[parent] accept error");
        exit(1);
    }

    if (close(listen_fd) < 0) {
        perror("[parent] close error");
        exit(1);
    }

    puts("[parent] The client is connected...");

    struct mmsghdr msg[2] = {0};
    struct iovec msg1[2]  = {0};
    struct iovec msg2     = {0};

	msg1[0].iov_base = STR_ONE;
	msg1[0].iov_len = strlen(STR_ONE);
	msg1[1].iov_base = STR_TWO;
	msg1[1].iov_len = strlen(STR_TWO);

	msg2.iov_base = STR_THREE;
	msg2.iov_len = strlen(STR_THREE);

	msg[0].msg_hdr.msg_iov = msg1;
	msg[0].msg_hdr.msg_iovlen = 2;

	msg[1].msg_hdr.msg_iov = &msg2;
	msg[1].msg_hdr.msg_iovlen = 1;

    /* send two ends of the pipe as ancillary data in two cmsg's (just for fun) */
    msg[0].msg_hdr.msg_control = cmsghdr_union.buf;
    msg[0].msg_hdr.msg_controllen = sizeof(cmsghdr_union.buf);

    struct cmsghdr* cmsg;
	cmsg = CMSG_FIRSTHDR(&msg[0].msg_hdr);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &pipefds[0], sizeof(int));

    cmsg = CMSG_NXTHDR(&msg[0].msg_hdr, cmsg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &pipefds[1], sizeof(int));

	ret = sendmmsg(fd, msg, 2, /*flags=*/0);
	if (ret < 0) {
        close(fd);
        perror("[parent] sendmmsg error\n");
        exit(1);
    }

    if (msg[0].msg_len != strlen(STR_ONE) + strlen(STR_TWO) ||
            msg[1].msg_len != strlen(STR_THREE)) {
        close(fd);
        fprintf(stderr, "[parent] sendmmsg error: not all messages were sent\n");
        exit(1);
    }

    printf("[parent] %d messages sent\n", ret);

    if (close(fd) < 0) {
        perror("[parent] close error");
        exit(1);
    }

    return 0;
}

int client(void) {
    int ret;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[child] socket error");
        exit(1);
    }

    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, UNIX_SOCKET_NAME, sizeof(address.sun_path));

    ret = -1;
    while (ret < 0) {
        /* wait until client is ready for read */
        errno = 0;
        ret = connect(fd, (struct sockaddr*)&address, sizeof(address));
        if (ret < 0 && errno != ENOENT && errno != ECONNREFUSED) {
            close(fd);
            perror("[child] connect error\n");
            exit(1);
        }
        sched_yield();
    }

    puts("[child] Connected to the server, receiving...");

	struct mmsghdr msgs[VLEN] = {0};
	struct iovec iovecs[VLEN] = {0};
	char bufs[VLEN][BUFSIZE + 1] = {0};

	for (int i = 0; i < VLEN; i++) {
		iovecs[i].iov_base         = bufs[i];
		iovecs[i].iov_len          = BUFSIZE;
		msgs[i].msg_hdr.msg_iov    = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

    /* receive two ends of the pipe as ancillary data in cmsg (must come in the first msg) */
    msgs[0].msg_hdr.msg_control = cmsghdr_union.buf;
    msgs[0].msg_hdr.msg_controllen = sizeof(cmsghdr_union.buf);

    ret = -1;
    while (ret < 0) {
        errno = 0;
        ret = recvmmsg(fd, msgs, VLEN, MSG_DONTWAIT, /*timeout=*/NULL);
        if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(fd);
            perror("[child] recvmmsg error");
            exit(1);
        }
        sched_yield();
    }

	printf("[child] %d messages received\n", ret);
	for (int i = 0; i < ret; i++) {
        if (!msgs[i].msg_len)
            continue;

		bufs[i][msgs[i].msg_len] = 0;
		printf("[child] message %d: %s\n", i + 1, bufs[i]);

        if (!msgs[i].msg_hdr.msg_control || !msgs[i].msg_hdr.msg_controllen)
            continue;

        struct cmsghdr* cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msgs[i].msg_hdr); cmsg != NULL;
                cmsg = CMSG_NXTHDR(&msgs[i].msg_hdr, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
                close(fd);
                fprintf(stderr, "[child] recvmmsg error: unexpected ancillary data\n");
                exit(1);
            }
            int* received_fds = (int*)CMSG_DATA(cmsg);
            pipefds[0] = received_fds[0];
            pipefds[1] = received_fds[1];
            break;
        }
	}

    if (pipefds[0] == -1 || pipefds[1] == -1) {
        close(fd);
        fprintf(stderr, "[child] recvmmsg error: received incorrect pipefds as ancillary data\n");
        exit(1);
    }

    /* test received pipe */
    ssize_t bytes;
    bytes = write(pipefds[1], STR_HELLO, sizeof(STR_HELLO));
    if (bytes < 0) {
        close(fd);
        perror("[child] write error\n");
        exit(1);
    }

    char buffer[128];
    bytes = 0;
    while (bytes <= 0) {
        errno = 0;
        bytes = read(pipefds[0], &buffer, sizeof(buffer));
        if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(fd);
            perror("[child] read error");
            exit(1);
        }
        sched_yield();
    }

    buffer[sizeof(buffer) - 1] = '\0';
    if (bytes < sizeof(buffer))
        buffer[bytes] = '\0';

    printf("[child] read on received pipe: %s\n", buffer);

    if (close(fd) < 0) {
        perror("[child] close error");
        exit(1);
    }

    return 0;
}

int main(int argc, char** argv) {
    int pid = fork();
    if (pid < 0) {
        perror("fork error");
        return 1;
    }

    if (pid == 0)
        return client();

    server();

    pid = wait(NULL); /* wait for child termination, just for sanity */
    if (pid < 0) {
        perror("[parent] wait error");
        return 1;
    }

    if (unlink(UNIX_SOCKET_NAME) < 0) {
        perror("[parent] unlink error");
        return 1;
    }

    return 0;
}
