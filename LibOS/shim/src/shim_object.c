#include <pal.h>
#include <shim_internal.h>

int object_wait_with_retry(PAL_HANDLE handle) {
    PAL_BOL ret;
    do {
        ret = DkSynchronizationObjectWait(handle, NO_TIMEOUT);
    } while (!ret &&
             (PAL_NATIVE_ERRNO == PAL_ERROR_INTERRUPTED || PAL_NATIVE_ERRNO == PAL_ERROR_TRYAGAIN));

    if (!ret) {
        debug("waiting on %p resulted in error %s", handle, pal_strerror(PAL_NATIVE_ERRNO));
        return -PAL_NATIVE_ERRNO;
    }
    return 0;
}
