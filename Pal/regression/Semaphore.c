#include "api.h"
#include "pal.h"
#include "pal_debug.h"

void helper_timeout(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1 = DkMutexCreate(1);

    if (!sem1) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    PAL_BOL rv = DkSynchronizationObjectWait(sem1, timeout);
    if (rv == PAL_FALSE)
        pal_printf("Locked binary semaphore timed out (%ld).\n", timeout);
    else
        pal_printf("Acquired locked binary semaphore!?! sem1 is %p (%ld)\n", sem1, timeout);

    DkObjectClose(sem1);
}

void helper_success(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1 = DkMutexCreate(0);

    if (!sem1) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    PAL_BOL rv = DkSynchronizationObjectWait(sem1, timeout);
    if (rv == PAL_TRUE)
        pal_printf("Locked binary semaphore successfully (%ld).\n", timeout);
    else
        pal_printf("Failed to lock binary semaphore: sem1 is %p\n", sem1);

    DkObjectClose(sem1);
}

int main(int argc, char** argv, char** envp) {
    helper_timeout(1000);
    /* Try again with timeout 0 (trylock) */
    helper_timeout(0);

    /* Try cases that should succeed */
    helper_success(NO_TIMEOUT);
    helper_success(0);
    return 0;
}
