#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void)
{
    char buf[15];
    char input_text[] = "Hello, world!";
    int fd = open("./pftmp/foo.txt", O_RDWR | O_CREAT, S_IRWXU);
    if (fd < 0) {
        printf("Cannot create file ./pftmp/foo.txt\n");
        goto out;
    }

    int num_bytes = write(fd, input_text, strlen(input_text));
    if (num_bytes < 0) {
        printf("Writing to file failed.\n");
        goto out;
    }

    rename("./pftmp/foo.txt", "./pftmp/bar.txt");

    fd = open("./pftmp/bar.txt", O_RDONLY);
    if (fd < 0) {
        printf("Cannot open renamed file ./pftmp/bar.txt\n");
        goto out;
    }

    num_bytes = read(fd, buf, sizeof(buf));
    if (num_bytes < 0) {
        printf("Reading from renamed file failed.\n");
        goto out;
    }

    if (strcmp(input_text, buf)) {
        printf ("File content mismatching.\n");
    }

    printf("TEST OK\n");

out:
    close(fd);
    return 0;
}
