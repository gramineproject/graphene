#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	int fd, size;
	char * message = "Hello, peer!";

	if (argc < 2) {
		printf("please specify FIFO file to write.\n");
		return -1;
	}

	fd = open(argv[1], O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		printf("can't open file handle.\n");
		return -1;
	} 

	size = write(fd, message, strlen(message));
	if (size < strlen(message)) {
		printf("failed to write().\n");
		return -1;
	} if (size == 0) {
		printf("return size is 0.\n");
		return -1;
	} else {
		printf("succeed to write.\n");
	}

	sleep(2);
	close(fd);


	return 0;
}
