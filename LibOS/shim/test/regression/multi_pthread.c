/* a simple helloworld test, with pthread usage */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define THREAD_NUM 32 
#define CON_THREAD_NUM 4

int counter = 0;

void* inc (void *arg)
{
    asm volatile( "lock; incl %0"
                 : "+m" (counter));
    return NULL;
}

int main(int argc, char** argv)
{
    for (int i = 0; i < THREAD_NUM; i++){
      pthread_t thread[CON_THREAD_NUM];
      for (int j = 0; j < CON_THREAD_NUM; j++)
          pthread_create(&thread[j], NULL, inc, NULL);
      for (int j = 0; j < CON_THREAD_NUM; j++)
          pthread_join(thread[j], NULL);
    }
    printf("%d Threads Created\n", counter);
    return 0;
}
