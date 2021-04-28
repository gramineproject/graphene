#include "pal.h"
#include "shim_internal.h"

int object_wait_with_retry(PAL_HANDLE handle) {
    int ret;
    do {
        ret = DkSynchronizationObjectWait(handle, NO_TIMEOUT);
    } while (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN);

    if (ret < 0) {
        log_error("waiting on an object with retry failed (%ld)\n", pal_to_unix_errno(ret));
        return pal_to_unix_errno(ret);
    }
    return 0;
}
