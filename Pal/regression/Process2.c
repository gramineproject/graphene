#include "api.h"
#include "pal.h"
#include "pal_regression.h"

int main(int argc, char** argv, char** envp) {
    PAL_STR args[1] = {0};
    PAL_HANDLE handle = NULL;
    if (DkProcessCreate("file:Bootstrap", args, &handle) < 0)
        return 1;
    return 0;
}
