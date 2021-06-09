/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file
 *
 * This file contains the implementation of `/dev` pseudo-filesystem.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int init_devfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("dev");

    /* Device minor numbers for pseudo-devices:
     * https://elixir.bootlin.com/linux/v5.9/source/drivers/char/mem.c#L950 */

    struct pseudo_node* null = pseudo_add_dev(root, "null");
    null->perm = PSEUDO_PERM_FILE_RW;
    null->dev.major = 1;
    null->dev.minor = 3;
    null->dev.dev_ops.read = &dev_null_read;
    null->dev.dev_ops.write = &dev_null_write;
    null->dev.dev_ops.seek = &dev_null_seek;
    null->dev.dev_ops.truncate = &dev_null_truncate;

    struct pseudo_node* zero = pseudo_add_dev(root, "zero");
    zero->perm = PSEUDO_PERM_FILE_RW;
    zero->dev.major = 1;
    zero->dev.minor = 5;
    zero->dev.dev_ops.read = &dev_zero_read;
    zero->dev.dev_ops.write = &dev_null_write;
    zero->dev.dev_ops.seek = &dev_null_seek;
    zero->dev.dev_ops.truncate = &dev_null_truncate;

    struct pseudo_node* random = pseudo_add_dev(root, "random");
    random->perm = PSEUDO_PERM_FILE_RW;
    random->dev.major = 1;
    random->dev.minor = 8;
    random->dev.dev_ops.read = &dev_random_read;
    /* writes in /dev/random add entropy in normal Linux, but not implemented in Graphene */
    random->dev.dev_ops.write = &dev_null_write;
    random->dev.dev_ops.seek = &dev_null_seek;

    struct pseudo_node* urandom = pseudo_add_dev(root, "urandom");
    urandom->perm = PSEUDO_PERM_FILE_RW;
    urandom->dev.major = 1;
    urandom->dev.minor = 9;
    /* /dev/urandom is implemented the same as /dev/random, so it has the same operations */
    urandom->dev.dev_ops = random->dev.dev_ops;

    struct pseudo_node* stdin = pseudo_add_link(root, "stdin", NULL);
    stdin->link.target = "/proc/self/fd/0";
    struct pseudo_node* stdout = pseudo_add_link(root, "stdout", NULL);
    stdout->link.target = "/proc/self/fd/0";
    struct pseudo_node* stderr = pseudo_add_link(root, "stderr", NULL);
    stderr->link.target = "/proc/self/fd/0";

    int ret = init_attestation(root);
    if (ret < 0)
        return ret;

    return 0;
}
