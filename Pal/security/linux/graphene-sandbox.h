#ifndef _LINUX_GRAPHENE_H
#define _LINUX_GRAPHENE_H

#include <linux/ioctl.h>
#include <linux/in.h>
#include <linux/in6.h>

#define GRAPHENE_UNIX_PREFIX_FMT	"/graphene/%08lx"
#define GRAPHENE_UNIX_PREFIX_SIZE	(sizeof("/graphene/") + 8 + 1) /* remember to plus 1 for the prefix "\0" */
#define GRAPHENE_MCAST_GROUP	"239.0.0.1"

#define GRM_SET_SANDBOX		_IOW('k', 16, void *)

#define GRAPHENE_LOADER_NAME	0001
#define GRAPHENE_UNIX_PREFIX	0002
#define GRAPHENE_MCAST_PORT	0003
#define GRAPHENE_FS_PATH	0004
#define GRAPHENE_NET_RULE	0005

#define GRAPHENE_POLICY_TYPES	0007

#define GRAPHENE_FS_RECURSIVE	0010
#define GRAPHENE_FS_READ	0020
#define GRAPHENE_FS_WRITE	0040

#define GRAPHENE_NET_BIND	0100

struct graphene_user_policy {
	int			type;
	const void *		value;
};

struct graphene_net_addr {
	union {
		struct in_addr 		sin_addr;
		struct in6_addr		sin6_addr;
	} addr;
	unsigned short		port_begin;
	unsigned short		port_end;
};

struct graphene_net_rule {
	unsigned short			family;
	struct graphene_net_addr	addr;
};

struct graphene_policies {
	int				npolicies;
	struct graphene_user_policy	policies[];
};

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct task_struct;
struct path;
struct qstr;

struct graphene_path {
	struct list_head	list;
	struct filename *	path;
	int			path_len;
	int			type;
};

#define ADDR_ANY		0x1
#define PORT_ANY		0x2

struct graphene_net {
	struct list_head	list;
	short			family;
	unsigned char		flags;
	struct graphene_net_addr	addr;
};

struct graphene_unix {
	atomic_t		count;
	struct list_head	list;
	struct path		root;
	struct qstr		prefix;
};

struct graphene_info {
	atomic_t		gi_count;
	struct filename *	gi_loader_name;
	char			gi_unix[GRAPHENE_UNIX_PREFIX_SIZE];
	struct list_head	gi_paths;
	struct list_head	gi_rpaths;
	struct list_head	gi_binds;
	struct list_head	gi_peers;
	unsigned short		gi_mcast_port;
	struct file *		gi_mcast_sock;
	u64			gi_gipc_session;
};

int check_open_path(struct graphene_info *gi, const char *path, int flags);

int check_stat_path(struct graphene_info *gi, const char *path);

int check_bind_addr(struct graphene_info *gi, struct socket *sock,
		     struct sockaddr *addr, int addrlen);

int check_connect_addr(struct graphene_info *gi, struct socket *sock,
		        struct sockaddr *addr, int addrlen);

int set_sandbox(struct file *file,
		const struct graphene_policies __user *gpolicies);

#endif /* __KERNEL__ */

#endif
