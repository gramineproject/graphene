/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

void helper_timeout(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1 = DkMutexCreate(1);

    if(!sem1) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    PAL_HANDLE rv = DkObjectsWaitAny(1, &sem1, timeout);
    if (rv == NULL)
        pal_printf("Locked binary semaphore timed out (%d).\n", timeout);
    else 
        pal_printf("Acquired locked binary semaphore!?! Got back %p; sem1 is %p (%d)\n", rv, sem1, timeout);
    
    DkObjectClose(sem1);
}

void helper_success(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1 = DkMutexCreate(0);

    if(!sem1) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    PAL_HANDLE rv = DkObjectsWaitAny(1, &sem1, timeout);
    if (rv == sem1)
        pal_printf("Locked binary semaphore successfully (%d).\n", timeout);
    else 
        pal_printf("Failed to lock binary semaphore: Got back %p; sem1 is %p\n", rv, sem1);
    
    DkObjectClose(sem1);
}


int main (int argc, char ** argv, char ** envp)
{
    helper_timeout(1000);
    /* Try again with timeout 0 (trylock) */
    helper_timeout(0);

    /* Try cases that should succeed */
    helper_success(NO_TIMEOUT);
    helper_success(0);
    return 0;
}
