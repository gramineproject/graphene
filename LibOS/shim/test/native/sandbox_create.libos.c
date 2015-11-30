/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <shim_unistd.h>

int main(int argc, char ** argv)
{
    mkdir("test_sandbox", 0700);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    addr.sin_port = htons(8000);

    struct net_sb net_sb;
    struct net_sb_rule net_sb_rule;
    net_sb.nrules = 1;
    net_sb.rules = &net_sb_rule;
    net_sb_rule.l_addrlen = 0;
    net_sb_rule.l_addr = NULL;
    net_sb_rule.r_addrlen = sizeof(struct sockaddr_in);
    net_sb_rule.r_addr = (void *) &addr;

    sandbox_create(SANDBOX_FS|SANDBOX_NET|SANDBOX_RPC,
                   "test_sandbox",
                   &net_sb);

    return 0;
}
