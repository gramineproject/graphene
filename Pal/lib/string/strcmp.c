#include "api.h"

int strcmp(const char* a, const char* b) {
    for (; *a && *b && *a == *b; a++, b++)
        ;
    return *a - *b;
}
