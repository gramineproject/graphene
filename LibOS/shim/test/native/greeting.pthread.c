/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */


/* greetings.c -- greetings program
 * 
 * Send a message from all processes with rank != 0 to process 0. Process 0
 * prints the messages received.
 * 
 * Input: none. Output: contents of messages received by process 0.
 * 
 * See Chapter 3, pp. 41 & ff in PPMPI. */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#define MAX_THREAD 1000

typedef struct
{
	int             id;
	int             nproc;
}               parm;

char            message[100];	/* storage for message  */
pthread_mutex_t msg_mutex = PTHREAD_MUTEX_INITIALIZER;
int             token = 0;

void* greeting(void *arg)
{
	parm           *p = (parm *) arg;
	int             id = p->id;
	int             i;

	if (id != 0)
		{
			/* Create message */
			while (1)
				{
					pthread_mutex_lock(&msg_mutex);
					if (token  == 0)
						{
							sprintf(message, "Greetings from process %d!", id);
							token++;
							pthread_mutex_unlock(&msg_mutex);
							break;
						}
					pthread_mutex_unlock(&msg_mutex);
					sleep(1);
				}
			/* Use strlen+1 so that '\0' gets transmitted */
		} else
		{				/* my_rank == 0 */
			for (i = 1; i < p->nproc; i++)
				{
					while (1)
						{
							pthread_mutex_lock(&msg_mutex);
							if (token == 1)
								{
									printf("%s\n", message);
									token--;
									pthread_mutex_unlock(&msg_mutex);
									break;
								}
							pthread_mutex_unlock(&msg_mutex);
							sleep(1);
						}
				}
		}

	return NULL;
}

int main(int argc, char *argv[])
{
	int             my_rank;	/* rank of process      */
	int             dest;		/* rank of receiver     */
	int             tag = 0;	/* tag for messages     */

	pthread_t      *threads;
	pthread_attr_t  pthread_custom_attr;
	parm           *p;

	int             n, i;

	if (argc != 2)
		{
			printf("Usage: %s n\n  where n is no. of thread\n", argv[0]);
			return 1;
		}
	n = atoi(argv[1]);

	if ((n < 1) || (n > MAX_THREAD))
		{
			printf("The no of thread should between 1 and %d.\n", MAX_THREAD);
			return 1;
		}
	threads = (pthread_t *) malloc(n * sizeof(*threads));
	pthread_attr_init(&pthread_custom_attr);

	p=(parm *)malloc(sizeof(parm)*n);
	/* Start up thread */

	for (i = 0; i < n; i++)
		{
			p[i].id = i;
			p[i].nproc = n;
			pthread_create(&threads[i], &pthread_custom_attr, greeting, (void *)(p+i));
		}

	/* Synchronize the completion of each thread. */

	for (i = 0; i < n; i++)
		{
			pthread_join(threads[i], NULL);
		}
	free(p);
}				/* main */
