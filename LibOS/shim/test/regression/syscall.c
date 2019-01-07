/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <sys/syscall.h>
#include <sysdep-x86_64.h>

int main(int argc, char ** argv)
{
    const char buf[] = "Hello world !\n";
    INLINE_SYSCALL(write, 3, 1, buf, sizeof(buf) - 1);
    return 0;
}
