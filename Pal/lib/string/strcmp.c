#include "assert.h"
#include "api.h"

int strcmp(const char* s1, const char* s2) {
    __UNUSED(s1);
    __UNUSED(s2);
    // not implemented.
    __abort();
    return 0;
}
