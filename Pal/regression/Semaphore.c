#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

static void helper_timeout(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1;
    int ret = DkMutexCreate(1, &sem1);

    if (ret < 0) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    ret = DkSynchronizationObjectWait(sem1, timeout);
    if (ret == -PAL_ERROR_TRYAGAIN) {
        pal_printf("Locked binary semaphore timed out (%ld).\n", timeout);
    } else if (ret == 0) {
        pal_printf("Acquired locked binary semaphore!?! sem1 is %p (%ld)\n", sem1, timeout);
    } else {
        pal_printf("Binary semaphore error: %d, sem1 is %p (%ld)\n", ret, sem1, timeout);
    }

    DkObjectClose(sem1);
}

static void helper_success(PAL_NUM timeout) {
    /* Create a binary semaphore */

    PAL_HANDLE sem1;
    int ret = DkMutexCreate(0, &sem1);

    if (ret < 0) {
        pal_printf("Failed to create a binary semaphore\n");
        return;
    }

    /* Wait on the binary semaphore with a timeout */
    ret = DkSynchronizationObjectWait(sem1, timeout);
    if (ret == 0)
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
