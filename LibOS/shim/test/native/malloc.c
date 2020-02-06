#include <stdio.h>
#include <stdlib.h>

static const size_t sizes[] = { 16, 32, 64, 128, 256, 512 };
int main(int argc, char** argv) {
    for (int i = 0; i < 100000; i++) {
        for (int j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
            if (!malloc(sizes[j])) {
                return 1;
            }
        }
    }
    return 0;
}
