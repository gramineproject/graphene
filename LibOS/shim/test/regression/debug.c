#include <stdio.h>

__attribute__((noinline)) static void func(void) {
    printf("hello\n");
    fflush(stdout);
}

int main(void) {
    func();
    return 0;
}
