#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char * argv[])
{
	int fd, ret;
	char message[1024] = {0};

	if (argc < 2) {
		printf("Please specify FIFO file to read.\n");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("failed to open file.\n");
		return -1;
	}

	if (lseek(fd, 0, SEEK_CUR) < 0)
	{
		ret = read(fd, message, 1024 -1 );
	} else {
		ret = pread(fd, message, 1024 - 1, 0);
	}
	
	if (ret < 0) {
		printf("pread() failure, error code is %d.\n", errno);		
	}else{
		message[ret] = '\0';

		printf("%s\n", message);
	}
	close(fd);

	return 0;
}
