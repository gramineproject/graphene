#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SRV_IP "127.0.0.1"
#define PORT   9930
#define BUFLEN 512
#define NPACK  10

enum { SINGLE, PARALLEL } mode = PARALLEL;
int do_fork                    = 0;

int pipefds[2];

int server(void) {
    struct sockaddr_in si_me, si_other;
    int s, i;
    socklen_t slen = sizeof(si_other);
    char buf[BUFLEN];

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "socket() failed\n");
        exit(1);
    }

    memset((char*)&si_me, 0, sizeof(si_me));
    si_me.sin_family      = AF_INET;
    si_me.sin_port        = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
        fprintf(stderr, "bind() failed\n");
        exit(1);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte = 0;
        if (write(pipefds[1], &byte, 1) != 1) {
            perror("write error");
            return 1;
        }
    }

    if (do_fork) {
        if (fork() > 0) {
            close(s);
            wait(NULL);
            return 0;
        }
    }

    for (i = 0; i < NPACK; i++) {
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr*)&si_other, &slen) == -1) {
            fprintf(stderr, "recvfrom() failed\n");
            exit(1);
        }

        printf("Received packet from %s:%d\nData: %s\n", inet_ntoa(si_other.sin_addr),
               ntohs(si_other.sin_port), buf);
    }

    close(s);
    if (do_fork)
        exit(0);
    return 0;
}

int client(void) {
    struct sockaddr_in si_other;
    int s, i;
    socklen_t slen   = sizeof(si_other);
    char buf[BUFLEN] = "hi";
    int res;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte = 0;
        if (read(pipefds[0], &byte, 1) != 1) {
            perror("read error");
            return 1;
        }
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "socket() failed\n");
        exit(1);
    }

    if (do_fork) {
        if (fork() > 0) {
            close(s);
            wait(NULL);
            return 0;
        }
    }

    memset((char*)&si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port   = htons((PORT));
    if (inet_aton(SRV_IP, &si_other.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    for (i = 0; i < 10; i++) {
        printf("Sending packet %d\n", i);
        sprintf(buf, "This is packet %d", i);
        if ((res = sendto(s, buf, BUFLEN, 0, (struct sockaddr*)&si_other, slen)) == -1) {
            fprintf(stderr, "sendto() failed\n");
            exit(1);
        }
    }

    close(s);
    if (do_fork)
        exit(0);
    return 0;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) {
            mode = SINGLE;
            return client();
        } else if (strcmp(argv[1], "server") == 0) {
            mode = SINGLE;
            return server();
        } else if (strcmp(argv[1], "fork") == 0) {
            do_fork = 1;
        } else {
            puts("Invalid option!");
            return 1;
        }
    }

    if (pipe(pipefds) < 0) {
        perror("pipe error");
        return 1;
    }

    int pid = fork();

    if (pid < 0) {
        perror("fork error");
        return 1;
    } else if (pid == 0) {
        return client();
    } else {
        int ret = server();
        if (waitpid(pid, NULL, -1) == -1) {
            perror("waitpid error");
            ret = 1;
        }
        return ret;
    }
}
