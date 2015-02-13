/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <linux/unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <asm-errno.h>

#include "utils.h"
#include "pal_security.h"
#include "graphene.h"

extern unsigned long pal_addr;

bool do_fork  = false;
bool do_trace = false;

extern struct pal_sec_info * pal_sec_info_addr;
extern struct config_store root_config;

int ioctl_set_graphene (struct config_store * config, int ndefault,
                        const struct graphene_user_policy * default_policies);

int init_child (int argc, const char ** argv, const char ** envp)
{
    const char * pipe_prefix = pal_sec_info_addr->pipe_prefix;
    char pipe_root[GRAPHENE_PIPEDIR_LEN + 20];
    snprintf(pipe_root, GRAPHENE_PIPEDIR_LEN + 20, GRAPHENE_PIPEDIR "/%08x",
             pal_sec_info_addr->domain_id);

    struct graphene_net_policy mcast_rules[2];
    memset(mcast_rules, 0, sizeof(struct graphene_net_policy) * 2);

    mcast_rules[0].family = AF_INET;
    mcast_rules[0].local.port_begin = pal_sec_info_addr->mcast_port;
    mcast_rules[0].local.port_end = pal_sec_info_addr->mcast_port;
    mcast_rules[0].peer.port_begin = 0;
    mcast_rules[0].peer.port_end = 65535;

    mcast_rules[1].family = AF_INET;
    mcast_rules[1].local.port_begin = 0;
    mcast_rules[1].local.port_end = 65535;
    inet_pton(AF_INET, MCAST_GROUP, &mcast_rules[1].peer.addr);
    mcast_rules[1].peer.port_begin = pal_sec_info_addr->mcast_port;
    mcast_rules[1].peer.port_end = pal_sec_info_addr->mcast_port;

    const struct graphene_user_policy default_policies[] = {
        { .type = GRAPHENE_LIB_NAME,     .value = PAL_LOADER, },
        { .type = GRAPHENE_LIB_ADDR,     .value = (void *) pal_addr, },
        { .type = GRAPHENE_UNIX_ROOT,    .value = pipe_root, },
        { .type = GRAPHENE_UNIX_PREFIX,  .value = pipe_prefix, },
        { .type = GRAPHENE_NET_RULE,     .value = &mcast_rules[0], },
        { .type = GRAPHENE_NET_RULE,     .value = &mcast_rules[1], },
    };

    return ioctl_set_graphene(&root_config, 6, default_policies);
}

int run_parent (pid_t child, int argc, const char ** argv, const char * envp)
{
    return 0;
}
