#include <stdio.h>            // printf 
#include <string.h>           // strerror
#include <errno.h>            // errno
#include <unistd.h>           // execl
#include <sys/ptrace.h>       // ptrace
#include <sys/user.h>         // user_regs_struct
#include <sys/personality.h>  // personality
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main(int argc, char *argv[], char *envp[]) {

	// create a child process
	int pid = fork();

	// if error occurs
	if (0 > pid) {
	printf("Error during forking: %s\n", strerror(errno));
	return 1;
	}

	// child process
	if (0 == pid) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		personality(ADDR_NO_RANDOMIZE);
		execve(argv[1], &(argv[1]), envp);
	}

	// parent process
	int status;
	struct user_regs_struct regs;
	int n;

	wait(&status);
	if(1407 == status) {
		char infilename[128], line[256], out[256];
		char* outfilename = "/tmp/pal_range";
		int mapfd, ret, outfd;
		unsigned long vas;
		unsigned long vae;

		sprintf(infilename, "/proc/%d/maps",pid);
		while((mapfd = open(infilename,O_RDONLY)) == -1);
		read(mapfd, &line, 256);

		/*scan for the virtual addresses*/
		n = sscanf(line, "%lX-%lX r-xp", &vas, &vae);
		if(n == 2)
		{
			outfd = open(outfilename, O_WRONLY|O_CREAT, S_IRUSR);
			memset(out,0,256);
			sprintf(out,"%lX,%lX\n", vas, vae);
			write(outfd, out, 256);
			close(outfd);
		}
		close(mapfd);
	}
	kill(pid,SIGKILL);
	return 0;
}
