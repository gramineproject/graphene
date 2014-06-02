/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <shim_table.h>

void main (int argc, char ** argv)
{
    shim_write(1, "Hello world\n", 12);
    shim_exit_group(0);
}
