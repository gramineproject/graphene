#include <sys/syscall.h>
#include <sysdep-x86_64.h>

int main(int argc, char** argv) {
    const char buf[] = "Hello world\n";
    INLINE_SYSCALL(write, 3, 1, buf, sizeof(buf) - 1);
    return 0;
}
