#include <pal.h>
#include <shim_internal.h>

int object_wait_with_retry(PAL_HANDLE handle) {
    PAL_HANDLE ret;
    do {
        ret = DkObjectsWaitAny(1, &handle, NO_TIMEOUT);
    } while (ret == NULL &&
             (PAL_NATIVE_ERRNO == PAL_ERROR_INTERRUPTED || PAL_NATIVE_ERRNO == PAL_ERROR_TRYAGAIN));
    if (ret == NULL) {
        debug("waiting on %p resulted in error %d", handle, PAL_NATIVE_ERRNO);
        return -PAL_NATIVE_ERRNO;
    }
    assert(ret == handle);
    return 0;
}
