/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Internal debug maps, used for SGX to communicate with debugger. We maintain it so that it is in a
 * consistent state any time the process is stopped (any add/delete is an atomic modification of one
 * pointer).
 *
 * The debug map is maintained inside the enclave, and the debugger is notified using
 * ocall_update_debugger().
 */

#ifndef SGX_RTLD_H
#define SGX_RTLD_H

/*
 * TODO: (GDB 8.2)
 *
 * To add the files in GDB, we use the 'add-symbol-file' command. In the GDB versions we support,
 * that command requires specifying a text section address (and, apparently, all the other
 * sections). In GDB 8.2, the 'text_addr' parameter is optional, and there is a new '-o offset'
 * option which allows to just specify load address for the whole file, and that's enough to load
 * all the sections.
 *
 * Once we are able to rely on newer GDB, we can get rid the section list (struct debug_section).
 * It's also possible that we will be able to use the r_debug structure instead, so that the same
 * mechanism is
 * used in Linux and Linux-SGX (even though in Linux-SGX we parse the structure manually in Python).
 */

struct debug_section {
    char* name;
    void* addr;

    struct debug_section* next;
};

struct debug_map {
    char* file_name;
    void* load_addr;
    struct debug_section* section;

    struct debug_map* _Atomic next;
};

#endif /* SGX_RTLD_H */
