/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This is our own copy of Linux file type permission macros. We keep it here to avoid including
 * <sys/stat.h> or <linux/stat.h>.
 */

#ifndef STAT_H
#define STAT_H

/* Play nice if someone did include the system headers. */
#ifndef S_IFREG

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)      (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)     (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)     (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#endif /* S_IFREG */

/*
 * We also define human-readable macros for common file permissions.
 * Inspired by Linux patch by Inigo Molnar (https://lwn.net/Articles/696231/).
 */

#define PERM_r________	0400
#define PERM_r__r_____	0440
#define PERM_r__r__r__	0444

#define PERM_rw_______	0600
#define PERM_rw_r_____	0640
#define PERM_rw_r__r__	0644
#define PERM_rw_rw_r__	0664
#define PERM_rw_rw_rw_	0666

#define PERM__w_______	0200
#define PERM__w__w____	0220
#define PERM__w__w__w_	0222

#define PERM_r_x______	0500
#define PERM_r_xr_x___	0550
#define PERM_r_xr_xr_x	0555

#define PERM_rwx______	0700
#define PERM_rwxr_x___	0750
#define PERM_rwxr_xr_x	0755
#define PERM_rwxrwxr_x	0775
#define PERM_rwxrwxrwx	0777

#define PERM__wx______	0300
#define PERM__wx_wx___	0330
#define PERM__wx_wx_wx	0333

#endif /* STAT_H */
