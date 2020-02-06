/* copied from http://www.daniweb.com/software-development/c/threads/179814 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SRV_BIND_IP "0.0.0.0"
#define SRV_IP      "127.0.0.1"
#define PORT        9930
#define BUFLEN      512
#define NPACK       10

const char* fname;

enum { SINGLE, PARALLEL } mode = PARALLEL;
int do_fork                    = 0;

int pipefds[2];

int server(void) {
    int conn, create_socket, new_socket, fd;
    socklen_t addrlen;
    int bufsize  = 1024;
    char* buffer = malloc(bufsize);
    struct sockaddr_in address;

    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) > 0)
        printf("The socket was created\n");

    address.sin_family = AF_INET;
    inet_pton(AF_INET, SRV_BIND_IP, &(address.sin_addr));
    address.sin_port = htons(PORT);

    if (bind(create_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        close(create_socket);
        exit(-1);
    }

    if (listen(create_socket, 3) < 0) {
        perror("listen");
        close(create_socket);
        exit(-1);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte = 0;
        if (write(pipefds[1], &byte, 1) != 1) {
            perror("write error");
            exit(1);
        }
    }

    addrlen    = sizeof(address);
    new_socket = accept(create_socket, (struct sockaddr*)&address, &addrlen);

    if (new_socket < 0) {
        perror("accept");
        close(create_socket);
        exit(-1);
    }

    close(create_socket);

    if (do_fork) {
        if (fork() > 0) {
            close(new_socket);
            wait(NULL);
            return 0;
        }
    }

    char buff[18] = {'\0'};
    if (inet_ntop(AF_INET, &address.sin_addr, buff, 18) <= 0)
        perror("address conversion");

    printf("The client %s is connected...\n", buff);

    if ((fd = open(fname, O_RDONLY, 0)) < 0) {
        perror("file open failed");
        close(new_socket);
        close(create_socket);
        exit(-1);
    }

    while ((conn = read(fd, buffer, bufsize)) > 0) {
        sendto(new_socket, buffer, conn, 0, 0, 0);
    }

    printf("Request completed\n");

    close(new_socket);
    if (do_fork)
        exit(0);
    return 0;
}

int client(void) {
    int count, create_socket;
    int bufsize  = 1024;
    char* buffer = malloc(bufsize);
    struct sockaddr_in address;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte = 0;
        if (read(pipefds[0], &byte, 1) != 1) {
            perror("read error");
            exit(1);
        }
    }

    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) >= 0)
        printf("The Socket was created\n");

    address.sin_family = AF_INET;
    inet_pton(AF_INET, SRV_IP, &address.sin_addr);
    address.sin_port = htons(PORT);
    if (connect(create_socket, (struct sockaddr*)&address, sizeof(address)) == 0) {
        printf("The connection was accepted with the server\n");
    } else {
        perror("accept");
        exit(0);
    }

    if (do_fork) {
        if (fork() > 0) {
            close(create_socket);
            wait(NULL);
            return 0;
        }
    }

    printf("Content:\n");

    while ((count = recv(create_socket, buffer, bufsize, 0)) > 0) {
        if (write(1, buffer, count) != count) {
            perror("write error");
            exit(1);
        }
    }

    printf("EOF\n");

    buffer[0] = 0;
    close(create_socket);
    if (do_fork)
        exit(0);
    return 0;
}

int main(int argc, char** argv) {
    char fnamebuf[40];
    strcpy(fnamebuf, argv[0]);
    strcat(fnamebuf, ".c");
    fname = fnamebuf;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) {
            mode = SINGLE;
            client();
            return 0;
        }

        if (strcmp(argv[1], "server") == 0) {
            mode = SINGLE;
            server();
            return 0;
        }

        if (strcmp(argv[1], "fork") == 0) {
            do_fork = 1;
            goto old;
        }
    } else {
    old:
        if (pipe(pipefds) < 0) {
            perror("pipe error");
            return 1;
        }

        int pid = fork();

        if (pid == 0)
            client();
        else {
            server();
            waitpid(pid, NULL, -1);
        }
    }

    return 0;
}
