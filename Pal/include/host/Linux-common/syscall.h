#ifndef SYSCALL_H_
#define SYSCALL_H_

#include <asm/unistd.h>

long do_syscall(long nr, ...);
long clone(int (*f)(void*), void* stack, int flags, void* arg, void* parent_tid, void* tls,
           void* child_tid, void (*exit_func)(int));
long vfork(void) __attribute__((returns_twice));

#define DO_SYSCALL(name, args...) do_syscall(__NR_##name, ##args)

#define IS_PTR_ERR(val) ((unsigned long)(val) >= (unsigned long)-4095L)
#define PTR_TO_ERR(val) ((long)val)
#define IS_UNIX_ERR(val) ((val) >= -133 /* EHWPOISON */ && (val) <= -1 /* EPERM */)

#endif // SYSCALL_H_
