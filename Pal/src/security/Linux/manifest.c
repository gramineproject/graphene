/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#define _GNU_SOURCE 1
#ifndef __GNUC__
#define __GNUC__ 1
#endif

#ifdef IN_PAL
# include "pal_defs.h"
# include "pal_linux_defs.h"
# include "pal.h"
# include "pal_internal.h"
# include "pal_linux.h"
# include "pal_debug.h"
# include "pal_error.h"
#else
# include "internal.h"
#endif

#include "graphene.h"
#include "pal_security.h"
#include "api.h"

#include <sys/socket.h>
#include <linux/unistd.h>
#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/errno.h>

static inline int is_file_uri (const char * uri)
{
    return uri[0] == 'f' && uri[1] == 'i' && uri[2] == 'l' && uri[3] == 'e' &&
           uri[4] == ':';
}

static inline const char * file_uri_to_path (const char * uri, int len)
{
    char * path;

    if (len == 5) {
        path = malloc(2);
        if (!path)
            return NULL;

        path[0] = '.';
        path[1] = 0;
        return path;
    }

    path = malloc(len - 4);
    if (!path)
        return NULL;

    memcpy(path, uri + 5, len - 4);
    return path;
}


static const char * __get_path (struct config_store * config, const char * key)
{
    char uri[CONFIG_MAX];

    if (get_config(config, key, uri, CONFIG_MAX) <= 0 ||
        !is_file_uri(uri))
        return NULL;

    return file_uri_to_path(uri, strlen(uri));
}

#define PRELOAD_MAX     16

int get_preload_paths (struct config_store * config, const char *** paths)
{
    char cfgbuf[CONFIG_MAX];

    if (get_config(config, "loader.preload", cfgbuf, CONFIG_MAX) <= 0)
        return 0;

    const char * p = cfgbuf, * n;
    const char * preload_paths[PRELOAD_MAX];
    int npreload = 0;

    while (*p && npreload < PRELOAD_MAX) {
        for (n = p ; *n && *n != ',' ; n++);

        if (!is_file_uri(p))
            goto next;

        if (!(preload_paths[npreload++] = file_uri_to_path(p, n - p)))
            return -ENOMEM;
next:
        p = *n ? n + 1 : n;
    }

    *paths = malloc(sizeof(const char *) * npreload);
    if (!(*paths))
        return -ENOMEM;

    memcpy((*paths), preload_paths, sizeof(const char *) * npreload);
    return npreload;
}

int get_fs_paths (struct config_store * config, const char *** paths)
{
    const char * root_path = __get_path(config, "fs.mount.root.uri");

    if (!root_path)
        return 0;

    char keys[CONFIG_MAX];
    int nkeys;

    if ((nkeys = get_config_entries(config, "fs.mount.other", keys,
                                    CONFIG_MAX)) < 0)
        nkeys = 0;

    *paths = malloc(sizeof(const char *) * (1 + nkeys));
    if (!(*paths))
        return -ENOMEM;

    (*paths)[0] = root_path;
    int npaths = 1;

    if (!nkeys)
        goto out;

    char key[CONFIG_MAX], * k = keys, * n;

    memcpy(key, "fs.mount.other.", 15);

    for (int i = 0 ; i < nkeys ; i++) {
        for (n = k ; *n ; n++);
        int len = n - k;
        memcpy(key + 15, k, len);
        memcpy(key + 15 + len, ".uri", 5);

        const char * path = __get_path(config, key);
        if (path)
            (*paths)[npaths++] = path;
        k = n + 1;
    }
out:
    return npaths;
}

int get_net_rules (struct config_store * config,
                   struct graphene_net_rule ** net_rules,
                   int * nbind_rules)
{
    char binds[CONFIG_MAX], peers[CONFIG_MAX];
    int nbinds, npeers;
    int nrules = 0;

    if ((nbinds = get_config_entries(config, "net.allow_bind", binds,
                                     CONFIG_MAX)) < 0)
        return 0;

    if ((npeers = get_config_entries(config, "net.allow_peer", peers,
                                     CONFIG_MAX)) < 0)
        return 0;

    struct graphene_net_rule * rules =
            malloc(sizeof(struct graphene_net_rule) * (nbinds + npeers));

    if (!rules)
        return -ENOMEM;

    for (int t = 0 ; t < 2 ; t ++) {
        char key[CONFIG_MAX], * k, * n;
        int nadded;

        if (t == 0) {
            if (!nbinds)
                continue;
            k = binds;
            nadded = nbinds;
            memcpy(key, "net.allow_bind.", 15);
        } else {
            if (!npeers)
                continue;
            k = peers;
            nadded = npeers;
            memcpy(key, "net.allow_peer.", 15);
        }

        for (int i = 0 ; i < nadded ; i++) {
            struct graphene_net_rule * r = &rules[nrules];
            char cfgbuf[CONFIG_MAX];

            for (n = k ; *n ; n++);
            int len = n - k;
            memcpy(key + 15, k, len + 1);
            key[15 + len] = 0;

            int cfglen = get_config(config, key, cfgbuf, CONFIG_MAX);
            if (cfglen <= 0)
                goto next;

            char * c = cfgbuf, * end = cfgbuf + cfglen;
            char * addr = c, * num;
            int addrlen;
            r->family = AF_INET;

            if (*c == '[') {
                r->family = AF_INET6;
                addr++;
                for ( ; c < end && *c != ']' ; c++);
                if (c == end)
                    goto next;
                addrlen = c - addr;
                c++;
                if (c == end || *c != ':')
                    goto next;
            } else {
                for ( ; c < end && *c != ':' ; c++);
                if (c == end)
                    goto next;
                addrlen = c - addr;
            }
            c++;

            if (c == end)
                goto next;

            num = c;
            for ( ; c < end && *c >= '0' && *c <= '9' ; c++);
            if (c == num)
                goto next;
            r->addr.port_end = r->addr.port_begin = atoi(num);

            if (c < end && *c == '-') {
                num = (++c);
                for ( ; c < end && *c >= '0' && *c <= '9' ; c++);
                if (c == num)
                    goto next;
                r->addr.port_end = atoi(num);
            }

            if (r->family == AF_INET) {
                if (!inet_pton4(addr, addrlen, &r->addr.addr))
                    goto next;
            } else {
                if (!inet_pton6(addr, addrlen, &r->addr.addr))
                    goto next;
            }

            nrules++;
next:
            k = n + 1;
        }

        if (t == 0)
            *nbind_rules = nrules;
    }

    *net_rules = rules;
    return nrules;
}

int ioctl_set_graphene (struct config_store * config, int ndefault,
                        const struct graphene_user_policy * default_policies)
{
    int ro = GRAPHENE_FS_READ, rw = ro | GRAPHENE_FS_WRITE;
    int ret = 0;
    const char ** preload_paths = NULL;
    const char ** fs_paths = NULL;
    struct graphene_net_rule * net_rules = NULL;
    int npreload = 0, nfs = 0, net = 0, bind_rules = 0;
    int fd = -1;
    int n = 0;

    npreload = get_preload_paths(config, &preload_paths);
    if (npreload < 0) {
        ret = npreload;
        goto out;
    }

    nfs = get_fs_paths(config, &fs_paths);
    if (nfs < 0) {
        ret = nfs;
        goto out;
    }

    net = get_net_rules(config, &net_rules, &bind_rules);
    if (net < 0) {
        ret = net;
        goto out;
    }

    struct graphene_policies * p =
                __alloca(sizeof(struct graphene_policies) +
                         sizeof(struct graphene_user_policy) *
                         (ndefault + npreload + nfs + net));

    memcpy(&p->policies[n], default_policies,
           sizeof(struct graphene_user_policy) * ndefault);
    n += ndefault;

    for (int i = 0 ; i < npreload ; i++) {
        p->policies[n].type = GRAPHENE_FS_PATH | ro;
        p->policies[n].value = preload_paths[i];
        n++;
    }

    for (int i = 0 ; i < nfs ; i++) {
        p->policies[n].type = GRAPHENE_FS_PATH | GRAPHENE_FS_RECURSIVE | rw;
        p->policies[n].value = fs_paths[i];
        n++;
    }

    for (int i = 0 ; i < net ; i++) {
        p->policies[n].type = GRAPHENE_NET_RULE;
        if (i < bind_rules)
            p->policies[n].type |= GRAPHENE_NET_BIND;
        p->policies[n].value = &net_rules[i];
        n++;
    }

    p->npolicies = n;

    fd = INLINE_SYSCALL(open, 3, GRAPHENE_FILE, O_RDONLY, 0);
    if (IS_ERR(fd)) {
        ret = -ERRNO(fd);
        goto out;
    }

    ret = INLINE_SYSCALL(ioctl, 3, fd, GRAPHENE_SET_TASK, p);
    ret = IS_ERR(ret) ? -ERRNO(ret) : 0;

out:
    if (fd != -1)
        INLINE_SYSCALL(close, 1, fd);

    if (preload_paths) {
        for (int i = 0 ; i < npreload ; i++)
            free((void *) preload_paths[i]);
        free(preload_paths);
    }

    if (fs_paths) {
        for (int i = 0 ; i < nfs ; i++)
            free((void *) fs_paths[i]);
        free(fs_paths);
    }

    if (net_rules)
        free(net_rules);

    return ret;
}
