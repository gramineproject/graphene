/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/errno.h>

#include "api.h"
#include "linux_utils.h"

int get_graphene_unix_socket_addr(uint64_t id, const char* name, struct sockaddr_un* addr) {
    /* Apparently there is no way to get this define without including whole "sys/socket.h". */
    addr->sun_family = /*AF_UNIX*/1;

    /* We use abstract UNIX sockets, which start with a nullbyte and actually look at the whole path
     * (even after the nullbyte). */
    memset(addr->sun_path, 0, sizeof(addr->sun_path));
    int ret = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "/graphene/%lu/%s", id,
                       name);
    if (ret < 0) {
        return ret;
    }
    if ((size_t)ret >= sizeof(addr->sun_path) - 1) {
        return -ERANGE;
    }
    return 0;
}
