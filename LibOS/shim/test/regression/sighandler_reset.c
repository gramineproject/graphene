#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/wait.h>

static int count;

void handler(int signum) {
  printf("Got signal %d\n", signum);
  fflush(stdout);
  count++;
}

int main() {
  struct sigaction action;
  action.sa_handler = handler;
  action.sa_flags = SA_RESETHAND; // one shot

  sigaction(SIGCHLD, &action, NULL);

  int pid = fork();
  if (pid < 0) {
      fprintf(stderr, "Fork failed\n");
      return 1;
  }

  if (pid == 0) {
      /* child signals parent -- only 1 must got through */
      kill(getppid(), SIGCHLD);
      kill(getppid(), SIGCHLD);
      exit(0);
  }

  wait(NULL);

  printf("Handler was invoked %d time(s).\n", count);

  if (count != 1)
     return 1;
  return 0;
}