#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    PAL_STR args[1] = {0};
    if (DkProcessCreate("file:Bootstrap", args) == NULL)
        return 1;
    return 0;
}
