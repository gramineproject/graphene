#include "pal.h"
#include "shim_internal.h"

int object_wait_with_retry(PAL_HANDLE handle) {
    int ret;
    do {
        ret = DkSynchronizationObjectWait(handle, NO_TIMEOUT);
    } while (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN);

    if (ret < 0) {
        log_error("waiting an object resulted in error %s",  pal_strerror(ret));
        return pal_to_unix_errno(ret);
    }
    return 0;
}
