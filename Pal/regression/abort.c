#include "api.h"
#include "pal.h"

// Required by asserts and _FORTIFY_SOURCE.
noreturn void __abort(void) {
    warn("ABORTED\n");
    // ENOTRECOVERABLE = 131
    DkProcessExit(131);
}
