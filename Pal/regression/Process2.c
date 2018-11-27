#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main (int argc, char ** argv, char ** envp)
{
    PAL_STR args[1] = { 0 };
    DkProcessCreate("file:Bootstrap", 0, args);
    return 0;
}
