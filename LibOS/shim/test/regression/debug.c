#include <stdio.h>

__attribute((noinline)) static void func() {
    printf("hello\n");
    fflush(stdout);
}

int main(void) {
    func();
    return 0;
}
