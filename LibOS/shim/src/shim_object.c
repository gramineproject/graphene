#include "pal.h"
#include "shim_internal.h"

int object_wait_with_retry(PAL_HANDLE handle) {
    PAL_BOL ret;
    do {
        ret = DkSynchronizationObjectWait(handle, NO_TIMEOUT);
    } while (!ret && (PAL_NATIVE_ERRNO() == PAL_ERROR_INTERRUPTED ||
                      PAL_NATIVE_ERRNO() == PAL_ERROR_TRYAGAIN));

    if (!ret) {
        log_error("waiting an object resulted in error %s", pal_strerror(PAL_NATIVE_ERRNO()));
        return -PAL_NATIVE_ERRNO();
    }
    return 0;
}
