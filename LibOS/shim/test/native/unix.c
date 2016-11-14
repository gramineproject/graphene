/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* copied from http://www.daniweb.com/software-development/c/threads/179814 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SRV_IP "127.0.0.1"
#define PORT 9930
#define BUFLEN 512
#define NPACK 10

const char * fname;

enum { SINGLE, PARALLEL } mode = PARALLEL;
int do_fork = 0;

int pipefds[2];

int server(void)
{
    int conn,create_socket,new_socket,addrlen,fd;
    int bufsize = 1024;
    char *buffer = malloc(bufsize);
    struct sockaddr_un address;

    if ((create_socket = socket(AF_UNIX,SOCK_STREAM,
                                0)) > 0)
        printf("The socket was created\n");

    address.sun_family = AF_UNIX;
    memcpy(address.sun_path,"u",10);

    if (bind(create_socket,(struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        close(create_socket);
        exit(-1);
    }

    if (listen(create_socket,3) < 0) {
        perror("listen");
        close(create_socket);
        exit(-1);
    }

    if (mode == PARALLEL) {
        close(pipefds[0]);
        char byte = 0;
        write(pipefds[1], &byte, 1);
    }

    addrlen = sizeof(address);
    new_socket = accept(create_socket,(struct sockaddr *)&address,
                        &addrlen);

    if (new_socket < 0) {
        perror("accept");
        close(create_socket);
        exit(-1);
    }

    close(create_socket);

    printf("The client is connected...\n");

    if (do_fork) {
        if (fork() > 0) {
            asm volatile ("int $3");
            close(new_socket);
            wait(NULL);
            return 0;
        }
    }

    if ((fd = open(fname,O_RDONLY,0)) < 0) {
        perror("File Open Failed");
        close(new_socket);
        exit(-1);
    }

    while((conn = read(fd,buffer,
                       bufsize)) > 0)
        sendto(new_socket,buffer,conn,0,0,0);

    printf("Request completed\n");

    close(new_socket);
    if (do_fork)
        exit(0);
    return 0;
}

int client(void)
{
    int count,create_socket;
    int bufsize = 1024;
    char *buffer = malloc(bufsize);
    struct sockaddr_un address;

    if (mode == PARALLEL) {
        close(pipefds[1]);
        char byte = 0;
        read(pipefds[0], &byte, 1);
    }

    if ((create_socket = socket(AF_UNIX,SOCK_STREAM,0)) >= 0)
        printf("The socket was created\n");

    address.sun_family = AF_UNIX;
    memcpy(address.sun_path,"u",10);

    if (connect(create_socket,(struct sockaddr *)&address,
                sizeof(address)) == 0)
        printf("The connection was accepted with the server\n");
    else {
        printf("The connection was not accepted with the server\n");
        exit(0);
    }

    if (do_fork) {
        if (fork() > 0) {
            close(create_socket);
            wait(NULL);
            return 0;
        }
    }

    printf("The contents of file are...\n\n");
    while((count=recv(create_socket,buffer,bufsize,0))>0)
        write(1,buffer,count);

    printf("\nEOF\n");

    buffer[0] = 0;
    close(create_socket);
    if (do_fork)
        exit(0);
    return 0;
}

int main(int argc, char ** argv)
{
    char fnamebuf[40];
    strcpy(fnamebuf, "unix");
    strcat(fnamebuf, ".c");
    fname = fnamebuf;

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
    }
    else {
old:
        pipe(pipefds);

        int pid = fork();

        if (pid == 0)
            client();
        else
            server();
    }

    return 0;
}
