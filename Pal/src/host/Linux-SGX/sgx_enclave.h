/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_linux.h"
#include "pal_security.h"

#define assert(cond) \
    do { if (!(cond)) INLINE_SYSCALL(exit_group, 1, 0); } while (0);

int ecall_pal_main (int argc, const char ** argv, const char ** envp);

int ecall_thread_start (void (*func) (void *, void *),
                        void * args, unsigned int * child_tid,
                        unsigned int tid);
