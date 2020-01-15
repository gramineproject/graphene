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

#define SRV_IP "127.0.0.1"
#define PORT 11111
#define BUFLEN 512

enum { SINGLE, PARALLEL } mode = PARALLEL;
int pipefds[2];

int server(void) {
    int create_socket, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen;
    char buffer[BUFLEN];

    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    int enable = 1;
    if (setsockopt(create_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    memset((char*)&address, 0, sizeof(address));
    address.sin_family      = AF_INET;
    address.sin_port        = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(create_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        close(create_socket);
        exit(1);
    }

    if (listen(create_socket, 3) < 0) {
        perror("listen");
        close(create_socket);
        exit(1);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte = 0;
        write(pipefds[1], &byte, 1);
    }

    addrlen    = sizeof(address);
    new_socket = accept(create_socket, (struct sockaddr*)&address, &addrlen);

    if (new_socket < 0) {
        perror("accept");
        close(create_socket);
        exit(1);
    }

    close(create_socket);

    puts("[server] client is connected...");

    sprintf(buffer, "Hello from server!\n");
    if (sendto(new_socket, buffer, strlen(buffer), 0, 0, 0) < 0) {
        perror("sendto");
        close(new_socket);
        exit(1);
    }

    puts("[server] done");
    close(new_socket);
    return 0;
}

int client(void) {
    int create_socket;
    struct sockaddr_in address;
    char buffer[BUFLEN];
    ssize_t count;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte = 0;
        read(pipefds[0], &byte, 1);
    }

    if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset((char*)&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port   = htons((PORT));
    if (inet_aton(SRV_IP, &address.sin_addr) == 0) {
        perror("inet_aton");
        exit(1);
    }

    if (connect(create_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("connect");
        exit(1);
    }

    printf("[client] receiving with MSG_PEEK: ");
    if ((count = recv(create_socket, buffer, sizeof(buffer), MSG_PEEK)) < 0) {
        perror("recv");
        exit(1);
    }
    fwrite(buffer, count, 1, stdout);

    printf("[client] receiving without MSG_PEEK: ");
    if ((count = recv(create_socket, buffer, sizeof(buffer), 0)) < 0) {
        perror("recv");
        exit(1);
    }
    fwrite(buffer, count, 1, stdout);

    printf("[client] checking how many bytes are left unread: ");
    if ((count = recv(create_socket, buffer, sizeof(buffer), 0)) < 0) {
        perror("recv");
        exit(1);
    }
    printf("%zu\n", count);

    puts("[client] done");
    close(create_socket);
    return 0;
}

int main(int argc, char** argv) {
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
    } else {
        pipe(pipefds);

        int pid = fork();

        if (pid == 0) {
            client();
        } else {
            server();
        }
    }

    return 0;
}
