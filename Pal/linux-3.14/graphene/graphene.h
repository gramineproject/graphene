#ifndef _LINUX_GRAPHENE_H
#define _LINUX_GRAPHENE_H

#include <linux/ioctl.h>
#include <linux/in.h>
#include <linux/in6.h>

#define GRAPHENE_FILE   "/dev/graphene"
#define GRAPHENE_MINOR		239

/* symbolic link this header file in include/linux */

/* This header needs to be included in include/linux/sched.h */

#ifndef __KERNEL__
# ifdef __user
#  undef __user
# endif
# define __user
#endif

#define GRAPHENE_LIB_NAME	0x01
#define GRAPHENE_LIB_ADDR	0x02
#define GRAPHENE_UNIX_ROOT	0x03
#define GRAPHENE_UNIX_PREFIX	0x04
#define GRAPHENE_NET_RULE	0x05
#define GRAPHENE_FS_PATH	0x06
#define GRAPHENE_FS_RECURSIVE	0x07
#define GRAPHENE_FS_READ	0x10
#define GRAPHENE_FS_WRITE	0x20

struct graphene_user_policy {
	int			type;
	const void __user *	value;
};

struct graphene_net_addr {
	union {
		struct in_addr 		sin_addr;
		struct in6_addr		sin6_addr;
	} addr;
	unsigned short		port_begin;
	unsigned short		port_end;
};

struct graphene_net_policy {
	unsigned short			family;
	struct graphene_net_addr	local, peer;
};

#define GRAPHENE_SET_TASK	_IO('k', 16)

struct graphene_policies {
	int				npolicies;
	struct graphene_user_policy	policies[];
};

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/path.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/rcupdate.h>

struct task_struct;
struct path;
struct qstr;

struct graphene_path {
	struct list_head	list;
	struct path		path;
	int			type;
};

#define LOCAL_ADDR_ANY		0x1
#define LOCAL_PORT_ANY		0x2
#define PEER_ADDR_ANY		0x4
#define PEER_PORT_ANY		0x8

struct graphene_net {
	struct list_head	list;
	short			family;
	unsigned char		flags;
	struct graphene_net_addr	local, peer;
};

struct graphene_unix {
	atomic_t		count;
	struct list_head	list;
	struct path		root;
	struct qstr		prefix;
};

/*
 * add the following line to struct task_struct (include/linux/sched.h):
 * 	struct graphene_struct *graphene;
 */
struct graphene_info {
	atomic_t		gi_count;
	struct path		gi_libexec;
	u64			gi_libaddr;
	struct path		gi_console[3];
	struct graphene_unix *	gi_unix;
	struct list_head	gi_paths;
	struct list_head	gi_rpaths;
	struct list_head	gi_net;
	u32			gi_gipc_session;
};

struct graphene_struct {
	atomic_t g_count;
	struct graphene_info __rcu *g_info;
	spinlock_t g_lock ____cacheline_aligned_in_smp;
};

#define GRAPHENE_ENABLED()	(current->graphene != NULL)

/* use this function in __put_task_struct (kernel/fork.c) */
int dup_graphene_struct(struct task_struct *task);

/* use this function in dup_task_struct (kernel/fork.c) */
void put_graphene_struct(struct task_struct *task);

/* add the following lines to common_perm (security/apparmor/lsm.c):
 * (when current->in_execve is true)
 * if (GRAPHNEE_ENABLED() && (error = graphene_execve_open(file))
 * 	return error;
 */
int graphene_execve_open(struct file *file);

/*
 * add the following lines to common_perm (security/apparmor/lsm.c):
 * if (GRAPHENE_ENABLED() &&
 *     (error = graphene_common_perm(op, path, mask)))
 * 	return error;
 *
 * add the following lines to apparmor_dentry_open (security/apparmor/lsm.c):
 * if (GRAPHENE_ENABLED() &&
 *     (error = graphene_common_perm(OP_OPEN, &file->path, mask)))
 * 	return error;
 */
int graphene_common_perm(int op, struct path *path, u32 mask);

/*
 * add the following lines to the initializer of apparmor_ops
 * (security/apparmor/lsm.c):
 * 	task_kill =			graphene_task_kill,
 */
int graphene_task_kill(struct task_struct *task, struct siginfo *info,
		       int sig, u32 secid);

/*
 * add the following lines to the initializer of apparmor_ops
 * (security/apparmor/lsm.c):
 * 	socket_bind =			graphene_socket_bind,
 * 	socket_listen =			graphene_socket_listen,
 * 	socket_connect =		graphene_socket_connect,
 * 	socket_sendmsg =		graphene_socket_sendmsg,
 * 	socket_recvmsg =		grapheen_socket_recvmsg,
 */
int graphene_socket_bind(struct socket *sock,
			 struct sockaddr *address, int addrlen);

int graphene_socket_listen(struct socket *sock, int backlog);
int graphene_socket_connect(struct socket *sock,
			    struct sockaddr *address, int addrlen);
int graphene_socket_sendmsg(struct socket *sock,
			    struct msghdr *msg, int size);
int graphene_socket_recvmsg(struct socket *sock,
			    struct msghdr *msg, int size, int flags);

u32 gipc_get_session(struct task_struct *tsk);

#endif /* __KERNEL__ */

#endif
