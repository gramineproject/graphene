/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_sandbox.c
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>
#include <shim_ipc.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

struct shim_sandbox {
    unsigned int   sbid;
    unsigned int   parent_sbid;
    IDTYPE         parent_vmid;
};

static struct shim_sandbox sandbox_info __attribute_migratable;

static inline void append_uri (char * uri, int prefix_len, char * append,
                               int append_len)
{
    if (prefix_len && uri[prefix_len - 1] == ':') {
        if (append[0] == '/')
            memcpy(uri + prefix_len, append + 1, append_len);
        else
            memcpy(uri + prefix_len, append, append_len + 1);
    } else {
        if (append[0] != '/')
            uri[prefix_len++] = '/';
        memcpy(uri + prefix_len, append, append_len + 1);
    }
}

static int isolate_fs (struct config_store * cfg, const char * path)
{
    struct shim_dentry * dent = NULL;
    int ret = 0;

    if ((ret = path_lookupat(NULL, path, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    if (!(dent->state & DENTRY_ISDIRECTORY)) {
        put_dentry(dent);
        return -ENOTDIR;
    }

    int dpath_len = 0;
    char * dpath = dentry_get_path(dent, true, &dpath_len);
    bool root_created = false;
    char t[CONFIG_MAX], u[CONFIG_MAX];
    ssize_t prefix_len;

    int nkeys;
    ssize_t keybuf_size;
    keybuf_size = get_config_entries_size(cfg, "fs.mount.other");
    if (keybuf_size <= 0)
        goto root;

    char * keybuf = __alloca(keybuf_size);
    nkeys = get_config_entries(cfg, "fs.mount.other", keybuf, keybuf_size);

    if (nkeys <= 0)
        goto root;

    char k[CONFIG_MAX], p[CONFIG_MAX];
    char * tmp = strcpy_static(k, "fs.mount.other.", CONFIG_MAX);
    const char * key = keybuf, * next = NULL;

    for (int n = 0 ; n < nkeys ; key = next, n++) {
        for (next = key ; *next ; next++);
        next++;
        size_t key_len = next - key - 1;
        memcpy(tmp, key, key_len);
        char * kp = tmp + key_len;
        ssize_t ulen, plen;
        bool is_chroot = false;

        /* Skip FS that are not chroot */
        strcpy_static(kp, ".type", k + CONFIG_MAX - kp);
        if (get_config(cfg, k, t, CONFIG_MAX) <= 0)
            continue;
        if (strpartcmp_static(t, "chroot"))
            is_chroot = true;

        strcpy_static(kp, ".uri", k + CONFIG_MAX - kp);
        if ((ulen = get_config(cfg, k, u, CONFIG_MAX)) <= 0)
            continue;

        strcpy_static(kp, ".path", k + CONFIG_MAX - kp);
        if ((plen = get_config(cfg, k, p, CONFIG_MAX)) <= 0)
            continue;

        if (plen >= dpath_len) {
            if (!memcmp(p, dpath, dpath_len)) {
                if (!p[dpath_len]) {
                    root_created = true;
                    debug("kept file rule: %s => %s\n", p, u);
                    continue;
                }
                if (p[dpath_len] != '/')
                    goto remove;
                /* keep this FS */
                continue;
            } else {
remove:
                if (!is_chroot) {
                    debug("kept file rule: %s => %s\n", p, u);
                    continue;
                }
                set_config(cfg, k, NULL);
                strcpy_static(kp, ".type", k + CONFIG_MAX - kp);
                set_config(cfg, k, NULL);
                strcpy_static(kp, ".uri", k + CONFIG_MAX - kp);
                set_config(cfg, k, NULL);
                debug("deleted file rule: %s => %s\n", p, u);
            }
        } else {
            if (memcmp(p, dpath, plen))
                goto remove;

            assert(dpath[plen]);
            if (dpath[plen] != '/')
                goto remove;
            if (!is_chroot) {
                root_created = true;
                debug("kept file rule: %s => %s\n", p, u);
                continue;
            }

            append_uri(u, ulen, dpath + plen, dpath_len - plen);
            set_config(cfg, k, dpath);
            strcpy_static(kp, "uri", k + CONFIG_MAX - kp);
            set_config(cfg, k, u);
            root_created = true;
            debug("added file rule: %s => %s\n", dpath, u);
        }
    }

root:
    if ((prefix_len = get_config(cfg, "fs.mount.root.uri", u, CONFIG_MAX)) > 0) {
        if (get_config(cfg, "fs.mount.root.type", t, CONFIG_MAX) > 0 &&
            strcmp_static(t, "chroot")) {
            /* remove the root FS */
            set_config(cfg, "fs.mount.root.uri",  NULL);
            set_config(cfg, "fs.mount.root.type", NULL);
            debug("deleted file rule: root\n");


            /* add another FS as part of the original root FS */
            if (!root_created) {
                append_uri(u, prefix_len, dpath, dpath_len);
                set_config(cfg, "fs.mount.other.root.path", dpath);
                set_config(cfg, "fs.mount.other.root.uri",  u);
                set_config(cfg, "fs.mount.other.root.type", "chroot");
                debug("added file rule: %s => %s\n", dpath, u);
            }
        }
    }

    return 0;
}

static int isolate_net (struct config_store * cfg, struct net_sb * sb)
{
    int nkeys;
    ssize_t keybuf_size;
    char k[CONFIG_MAX], * keybuf;

    keybuf_size = get_config_entries_size(cfg, "net.rules");
    if (keybuf_size <= 0)
        goto add;

    keybuf = __alloca(keybuf_size);
    nkeys = get_config_entries(cfg, "net.rules", keybuf, keybuf_size);

    if (nkeys <= 0)
        goto add;

    const char * key = keybuf, * next = NULL;
    memcpy(k, "net.rules.", 10);

    for (int n = 0 ; n < nkeys ; key = next, n++) {
        for (next = key ; *next ; next++);
        next++;
        int key_len = next - key - 1;
        memcpy(k + 10, key, key_len);
        k[10 + key_len] = 0;

        set_config(cfg, k, NULL);
    }

add:
    if (!sb)
        return 0;

    for (int i = 0 ; i < sb->nrules ; i++) {
        struct net_sb_rule * r = &sb->rules[i];
        char u[CONFIG_MAX];
        int ulen;
        int family = -1;

undo:
        ulen = 0;
        for (int turn = 0 ; turn < 2 ; turn++) {
            struct sockaddr * addr = turn ? r->r_addr : r->l_addr;

            if (turn)
                u[ulen++] = ':';

            if (!addr) {
                if (family == -1 || family == AF_INET)
                    ulen += snprintf(u + ulen, CONFIG_MAX - ulen,
                                     "0.0.0.0:0-65535");
                else
                    ulen += snprintf(u + ulen, CONFIG_MAX - ulen,
                                     "[0:0:0:0:0:0:0:0]:0-65535]");
            } else {
                if (addr->sa_family == AF_INET) {
                    if (family == AF_INET6)
                        goto next;
                    family = AF_INET;
                    struct sockaddr_in * saddr = (void *) addr;
                    unsigned char * a = (void *) &saddr->sin_addr.s_addr;
                    ulen += snprintf(u + ulen, CONFIG_MAX - ulen,
                                     "%d.%d.%d.%d:%u",
                                     a[0], a[1], a[2], a[3],
                                     __ntohs(saddr->sin_port));
                    continue;
                }

                if (addr->sa_family == AF_INET6) {
                    if (family == AF_INET)
                        goto next;
                    if (turn && family == -1) {
                        family = AF_INET6;
                        goto undo;
                    }

                    family = AF_INET6;
                    struct sockaddr_in6 * saddr = (void *) addr;
                    unsigned short * a = (void *) &saddr->sin6_addr.s6_addr;
                    ulen += snprintf(u + ulen, CONFIG_MAX - ulen,
                                     "[%d:%d:%d:%d:%d:%d:%d:%d]:%u",
                                     a[0], a[1], a[2], a[3],
                                     a[4], a[5], a[6], a[7],
                                     __ntohs(saddr->sin6_port));
                    continue;
                }

                goto next;
            }
        }

        snprintf(k + 10, CONFIG_MAX - 10, "%d", i + 1);
        set_config(cfg, k, u);
        debug("added net rule: %s\n", u);
next:
        continue;
    }

    return 0;
}

static void * __malloc (size_t size)
{
    return malloc(size);
}

static void __free (void * mem)
{
    free(mem);
}

struct cfg_arg {
    PAL_HANDLE handle;
    int offset;
};

static int __write (void * f, void * buf, int len)
{
    struct cfg_arg * arg = f;

    int bytes = DkStreamWrite(arg->handle, arg->offset, len, buf, NULL);
    if (!bytes)
        return -PAL_ERRNO;

    arg->offset += bytes;
    return bytes;
}

long shim_do_sandbox_create (int flags, const char * fs_sb,
                             struct net_sb * net_sb)
{
    unsigned int sbid;
    char uri[24];
    PAL_HANDLE handle = NULL;

    int ret = create_handle("file:sandbox-", uri, 24, &handle, &sbid);
    if (ret < 0)
        return ret;

    debug("create manifest: %s\n", uri);

    struct config_store * newcfg = __alloca(sizeof(struct config_store));
    memset(newcfg, 0, sizeof(struct config_store));
    newcfg->malloc = __malloc;
    newcfg->free = __free;

    if ((ret = copy_config(root_config, newcfg)) < 0) {
        newcfg = NULL;
        goto err;
    }

    if (flags & SANDBOX_FS)
        if ((ret = isolate_fs(newcfg, fs_sb)) < 0)
            goto err;

    if (flags & SANDBOX_NET)
        if ((ret = isolate_net(newcfg, net_sb)) < 0)
            goto err;

    struct cfg_arg arg;
    arg.handle = handle;
    arg.offset = 0;

    if ((ret = write_config(&arg, __write, newcfg)) < 0)
        goto err;

    DkObjectClose(handle);

    PAL_BOL success = DkProcessSandboxCreate(uri, flags & SANDBOX_RPC ?
                                             PAL_SANDBOX_PIPE : 0);

    if (!success) {
        ret = -PAL_ERRNO;
        goto err;
    }

    if (sandbox_info.sbid) {
        if (!sandbox_info.parent_sbid ||
            sandbox_info.parent_vmid != cur_process.vmid) {
            sandbox_info.parent_sbid = sandbox_info.sbid;
            sandbox_info.parent_vmid = cur_process.vmid;
        }
    }

    if (flags & SANDBOX_RPC)
        del_all_ipc_ports(0);

    if ((ret = free_config(root_config)) < 0)
        goto err;

    handle = DkStreamOpen(uri, PAL_ACCESS_RDONLY, 0, 0, 0);

    if (!handle)
        return -PAL_ERRNO;

    root_config = newcfg;
    sandbox_info.sbid = sbid;
    return sbid;

err:
    free_config(newcfg);
    DkStreamDelete(handle, 0);
    DkObjectClose(handle);
    return ret;
}

int shim_do_sandbox_attach (unsigned int sbid)
{
    return -ENOSYS;
}

long shim_do_sandbox_current (void)
{
    return sandbox_info.sbid;
}
