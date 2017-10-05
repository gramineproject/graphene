/*
 *  graphene-sandbox.c
 *
 *  Copyright (C) 2013-, Chia-Che Tsai, Bhushan Jain and Donald Porter
 *
 *  Manage the graphene information and security policies.
 */

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp_states.h>
#include "graphene-sandbox.h"

enum {
	OP_OPEN,
	OP_STAT,
	OP_BIND,
	OP_LISTEN,
	OP_ACCEPT,
	OP_CONNECT,
	OP_SENDMSG,
	OP_RECVMSG,
};

static atomic64_t unix_prefix_counter	= ATOMIC64_INIT(1);
static atomic64_t gipc_session		= ATOMIC64_INIT(1);;

static void drop_graphene_info(struct graphene_info *info)
{
	struct graphene_path *p, *n;

	list_for_each_entry_safe(p, n, &info->gi_paths, list) {
		__putname(p->path);
		kfree(p);
	}

	list_for_each_entry_safe(p, n, &info->gi_rpaths, list) {
		__putname(p->path);
		kfree(p);
	}

	if (info->gi_loader_name)
		__putname(info->gi_loader_name);

	if (info->gi_mcast_sock)
		fput(info->gi_mcast_sock);

	kfree(info);
}

void put_graphene_info(struct graphene_info *info)
{
	if (!atomic_dec_return(&info->gi_count))
		drop_graphene_info(info);
}

int check_execve_path(struct graphene_info *gi, const char *path)
{
	if (!strncmp(gi->gi_loader_name->name, path, strlen(path))) {
#ifdef GRAPHENE_DEBUG
		printk(KERN_INFO "Graphene: DENY EXEC PID %d PATH %s\n",
		       path);
#endif
		return -EPERM;
	}

#ifdef GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: ALLOW EXEC PID %d PATH %s\n",
	       path);
#endif
	return 0;
}

static int check_path(struct graphene_path *gp,
		      const char *path, int len, u32 mask,
		      int is_recursive)
{
	if (!strncmp(gp->path->name, path, len))
		return 0;

	if (mask & (MAY_READ|MAY_EXEC|MAY_ACCESS)) {
		if (!(gp->type & GRAPHENE_FS_READ))
			return -EPERM;
	}

	if (mask & (MAY_WRITE|MAY_APPEND)) {
		if (!(gp->type & GRAPHENE_FS_WRITE))
			return -EPERM;
	}

	return 1;
}

static int __common_file_perm(struct graphene_info *gi,
			      const char *path, int op, u32 mask)
{
	struct graphene_path *p;
	int len = strlen(path);
	int rv = 0;

	list_for_each_entry(p, &gi->gi_paths, list) {
		rv = check_path(p, path, len, mask, false);
		if (rv)
			goto out;
	}

	list_for_each_entry(p, &gi->gi_rpaths, list) {
		rv = check_path(p, path, len, mask, true);
		if (rv)
			goto out;
	}

	rv = -EPERM;
out:
	if (rv >= 0) {
		rv = 0;
#ifdef GRAPHENE_DEBUG
		printk(KERN_INFO "Graphene: ALLOW PID %d PATH %s\n",
		       path);
	} else {
		printk(KERN_INFO "Graphene: DENY PID %d PATH %s\n",
		       path);
#endif
	}
	return rv;
}

int __unix_perm(struct graphene_info *gi,
		struct sockaddr *address, int addrlen)
{
	const char * sun_path =
		((struct sockaddr_un *) address)->sun_path;

	if (!gi->gi_unix[1])
		return -EPERM;

	if (!memcmp(sun_path, gi->gi_unix, sizeof(gi->gi_unix)))
		return 0;

#ifdef GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: DENY PID %d SOCKET %s\n",
	       current->pid, sun_path);
#endif
	return -EPERM;
}

static int net_cmp(int family, bool addr_any, bool port_any,
		   struct graphene_net_addr *ga,
		   struct sockaddr *addr, int addrlen)
{
	switch(family) {
	case AF_INET: {
		struct sockaddr_in *a = (void *) addr;

		if (!addr_any) {
			if (a->sin_addr.s_addr != ga->addr.sin_addr.s_addr)
				return 1;
		}
		if (!port_any) {
			unsigned short port = ntohs(a->sin_port);
			if (!(port >= ga->port_begin && port <= ga->port_end))
				return 1;
		}

		break;
	}
#ifdef CONFIG_IPV6
	case AF_INET6: {
		struct sockaddr_in6 *a6 = (void *) addr;

		if (!addr_any) {
			if (memcmp(&a6->sin6_addr, &ga->addr.sin6_addr,
				   sizeof(struct in6_addr)))
				return 1;
		}
		if (!port_any) {
			unsigned short port = ntohs(a6->sin6_port);
			if (!(port >= ga->port_begin && port <= ga->port_end))
				return 1;
		}

		break;
	}
#endif
	}

	return 0;
}

#ifdef GRAPHENE_DEBUG
static void print_net(int allow, int family, int op, struct sockaddr *addr,
		      int addrlen)
{
	const char *allow_str = allow ? "ALLOW" : "DENY";
	const char *op_str = "UNKNOWN OP";

	switch(op) {
		case OP_BIND:		op_str = "BIND";	break;
		case OP_LISTEN:		op_str = "LISTEN";	break;
		case OP_CONNECT:	op_str = "CONNECT";	break;
		case OP_SENDMSG:	op_str = "SENDMSG";	break;
		case OP_RECVMSG:	op_str = "RECVMSG";	break;
	}

	if (!addr) {
		printk(KERN_INFO "Graphene: %s %s PID %d SOCKET\n",
		       allow_str, op_str, current->pid);
		return;
	}

	switch(family) {
	case AF_INET: {
		struct sockaddr_in *a = (void *) addr;
		u8 *a1 = (u8 *) &a->sin_addr.s_addr;

		printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
		       "%d.%d.%d.%d:%d\n",
		       allow_str, op_str, current->pid,
		       a1[0], a1[1], a1[2], a1[3], ntohs(a->sin_port));
		}
		break;

#ifdef CONFIG_IPV6
	case AF_INET6: {
		struct sockaddr_in6 *a = (void *) addr;
		u16 *a1 = (u16 *) &a->sin6_addr.s6_addr;

		printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
		       "[%d.%d.%d.%d:%d:%d:%d:%d]:%d\n",
		       allow_str, op_str, current->pid,
		       a1[0], a1[1], a1[2], a1[3],
		       a1[4], a1[5], a1[6], a1[7], ntohs(a->sin6_port));
		}
		break;
#endif
	}
}
#else
# define print_net(...) do {} while (0)
#endif

/*
 * network rules:
 *    bind:
 *        input addr/port match bind addr/port
 *    connect:
 *        input addr/port match peer addr/port
 *    sendmsg:
 *        EITHER stream socket OR no input addr/port OR
 *        input addr/port match peer addr/port
 *    recvmsg:
 *        EITHER stream socket OR connected
 */
static
int __common_net_perm(struct graphene_info *gi, int op, struct socket *sock,
		      struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;
	struct list_head *head;
	struct graphene_net *gn;

	if (sk->sk_type != SOCK_STREAM && sk->sk_type != SOCK_DGRAM)
		return -EPERM;

#ifdef CONFIG_IPV6
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
#else
	if (sk->sk_family != AF_INET)
#endif
		return -EPERM;

	switch(op) {
		case OP_BIND:
			head = &gi->gi_binds;
			break;
		case OP_CONNECT:
		case OP_SENDMSG:
			head = &gi->gi_peers;
			break;
		default:
			print_net(1, sk->sk_family, op, address, addrlen);
			return 0;
	}

	BUG_ON(!address);

	if (list_empty(head))
		goto no_rules;

	list_for_each_entry(gn, head, list) {
		if (gn->family != sk->sk_family)
			continue;

		if (net_cmp(sk->sk_family,
			    gn->flags & ADDR_ANY, gn->flags & PORT_ANY,
			    &gn->addr, address, addrlen))
			continue;

		print_net(1, sk->sk_family, op, address, addrlen);
		return 0;
	}

no_rules:
	if (gi->gi_mcast_port && sk->sk_family == AF_INET &&
	    ((struct sockaddr_in *) address)->sin_port == gi->gi_mcast_port) {
		print_net(1, AF_INET, op, address, addrlen);
		return 0;
	}

	print_net(0, sk->sk_family, op, address, addrlen);
	return -EPERM;
}

int check_bind_addr(struct graphene_info *gi,
		    struct socket *sock,
		    struct sockaddr *address, int addrlen)
{
	if (!sock || !sock->sk)
		return 0;

	if (sock->sk->sk_family == PF_UNIX) {
		if (sock->sk->sk_type != SOCK_STREAM)
			return -EPERM;

		return __unix_perm(gi, address, addrlen);
	}

	return __common_net_perm(gi, OP_BIND, sock, address, addrlen);
}

int check_connect_addr(struct graphene_info *gi,
		       struct socket *sock,
		       struct sockaddr *address, int addrlen)
{
	if (!sock || !sock->sk)
		return 0;

	if (sock->sk->sk_family == PF_UNIX) {
		if (sock->sk->sk_type != SOCK_STREAM)
			return -EPERM;

		return __unix_perm(gi, address, addrlen);
	}

	return __common_net_perm(gi, OP_CONNECT, sock, address,
				 addrlen);
}

#if 0
int check_sendmsg_addr(strut graphene_info *gi,
		       struct socket *sock,
		       struct msghdr *msg, int size)
{
	if (!sock || !sock->sk || sock->sk->sk_family == PF_UNIX)
		return 0;

	if (sock->sk->sk_type == SOCK_STREAM)
		return 0;

	if (!msg->msg_name)
		return 0;


	return __common_net_perm(gi, OP_SENDMSG, sock,
				 msg->msg_name, msg->msg_namelen);
}

int check_recvmsg_addr(struct grapheen_info *gi,
		       struct socket *sock,
		       struct msghdr *msg, int size, int flags)
{
	if (!sock || !sock->sk || sock->sk->sk_family == PF_UNIX)
		return 0;

	if (sock->sk->sk_type == SOCK_STREAM)
		return 0;

	return __common_net_perm(gi, OP_RECVMSG, sock, NULL, 0);
}
#endif

#ifdef GRAPHENE_DEBUG
static void print_net_rule(const char *fmt, struct graphene_net *n)
{
# ifdef CONFIG_IPV6
#  define ADDR_STR_MAX	128
# else
#  define ADDR_STR_MAX	48
# endif

	char str[ADDR_STR_MAX];
	int len = 0;

	if (n->flags & ADDR_ANY) {
		str[len++] = 'A';
		str[len++] = 'N';
		str[len++] = 'Y';
		str[len++] = ':';
	} else {
		switch(n->family) {
		case AF_INET: {
			u8 *ip = (u8 *) &n->addr.addr.sin_addr.s_addr;
			len += snprintf(str + len,
					ADDR_STR_MAX - len,
					"%u.%u.%u.%u:",
					ip[0], ip[1], ip[2], ip[3]);
			}
			break;
#ifdef CONFIG_IPV6
		case AF_INET6: {
			u16 *ip = (u16 *) &n->addr.addr.sin6_addr.s6_addr;
			len += snprintf(str + len,
					ADDR_STR_MAX - len,
					"[%u:%u:%u:%u:%u:%u:%u:%u]:",
					ip[0], ip[1], ip[2], ip[3],
					ip[4], ip[5], ip[6], ip[7]);
			}
			break;
#endif /* CONFIG_IPV6 */
		}
	}

	if (n->flags & PORT_ANY) {
		str[len++] = 'A';
		str[len++] = 'N';
		str[len++] = 'Y';
	} else {
		if (n->addr.port_begin == n->addr.port_end)
			len += snprintf(str + len, ADDR_STR_MAX - len,
					"%u", n->addr.port_begin);
		else
			len += snprintf(str + len, ADDR_STR_MAX - len,
					"%u-%u",
					n->addr.port_begin, n->addr.port_end);
	}

	BUG_ON(len >= ADDR_STR_MAX);
	str[len] = 0;
	printk(fmt, current->pid, str);
}
#else
# define print_net_rule(...) do {} while (0)
#endif

static int set_net_rule(struct graphene_net_rule *nr, struct graphene_info *gi,
			bool bind)
{
	struct graphene_net *n;

#ifdef CONFIG_IPV6
	if (nr->family != AF_INET && nr->family != AF_INET6)
#else
	if (nr->family != AF_INET)
#endif
		return -EINVAL;

	n = kmalloc(sizeof(struct graphene_net), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->family  = nr->family;
	n->flags   = 0;
	n->addr    = nr->addr;

	switch(n->family) {
	case AF_INET:
		if (!n->addr.addr.sin_addr.s_addr)
			n->flags |= ADDR_ANY;
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		if (!memcmp(&n->addr.addr.sin6_addr.s6_addr, &in6addr_any, 16))
			n->flags |= ADDR_ANY;
		break;
#endif /* CONFIG_IPV6 */
	}

	if (n->addr.port_begin == 0 && n->addr.port_end == 65535)
		n->flags |= PORT_ANY;

	INIT_LIST_HEAD(&n->list);
	if (bind) {
		list_add_tail(&n->list, &gi->gi_binds);
		print_net_rule(KERN_INFO "Graphene: PID %d NET BIND %s\n", n);
	} else {
		list_add_tail(&n->list, &gi->gi_peers);
		print_net_rule(KERN_INFO "Graphene: PID %d NET PEER %s\n", n);
	}
	return 0;
}

#if 0
u64 gipc_get_session(struct task_struct *tsk)
{
	struct graphene_info *gi = get_graphene_info(tsk->graphene);
	return gi ? gi->gi_gipc_session : 0;
}
#endif

static int update_sandbox(struct file *file, struct graphene_info *new);

int set_sandbox(struct file *file,
		const struct graphene_policies __user *gpolicies)
{
	const struct graphene_user_policy __user *policies;
	int npolicies;
	struct graphene_info *gi;
	struct graphene_user_policy ptmp;
	struct graphene_path *p;
	struct filename *tmp = NULL, *new;
	char *kname;
	int rv, i;

	policies = gpolicies->policies;
	rv = copy_from_user(&npolicies, &gpolicies->npolicies, sizeof(int));
	if (rv)
		return -EFAULT;

	if (npolicies && !policies)
		return -EINVAL;

	gi = kmalloc(sizeof(struct graphene_info), GFP_KERNEL);
	if (!gi)
		return -ENOMEM;

	tmp = __getname();
	rv = -ENOMEM;
	if (unlikely(!tmp))
		goto out;

	kname = (char *) tmp;
	memset(gi, 0, sizeof(struct graphene_info));
	INIT_LIST_HEAD(&gi->gi_paths);
	INIT_LIST_HEAD(&gi->gi_rpaths);
	INIT_LIST_HEAD(&gi->gi_binds);
	INIT_LIST_HEAD(&gi->gi_peers);
	gi->gi_gipc_session = atomic64_inc_return(&gipc_session);

#ifdef GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: PID %d GIPC SESSION %llu\n",
	       current->pid, gi->gi_gipc_session);
#endif

	for (i = 0 ; i < npolicies ; i++) {
		int type, flags;
		rv = copy_from_user(&ptmp, policies + i,
				    sizeof(struct graphene_user_policy));
		if (rv) {
			rv = -EFAULT;
			goto err;
		}

		if (!ptmp.value) {
			rv = -EINVAL;
			goto err;
		}

		type = ptmp.type & GRAPHENE_POLICY_TYPES;
		flags = ptmp.type & ~type;

		switch(type) {
		case GRAPHENE_LOADER_NAME:
			rv = strncpy_from_user(kname, ptmp.value, PATH_MAX);
			if (rv < 0)
				goto err;

			new = kmalloc(sizeof(*new), GFP_KERNEL);
			rv = -ENOMEM;
			if (!new)
				goto err;

			new->name = kname;
			gi->gi_loader_name = new;

			tmp = __getname();
			if (!tmp)
				goto err;
			kname = (char *) tmp;
#ifdef GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d LIB NAME %s\n",
			       current->pid, new->name);
#endif
			break;

		case GRAPHENE_UNIX_PREFIX: {
			unsigned long token =
				atomic64_inc_return(&unix_prefix_counter);

			gi->gi_unix[0] = '\0';
			snprintf(gi->gi_unix + 1, sizeof(gi->gi_unix) - 1,
				 GRAPHENE_UNIX_PREFIX_FMT, token);
			gi->gi_unix[sizeof(gi->gi_unix) - 1] = '/';

			rv = copy_to_user((void *) ptmp.value, &token,
					  sizeof(unsigned long));
			if (rv) {
				rv = -EFAULT;
				goto err;
			}

#ifdef GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d UNIX PREFIX %s\n",
			       current->pid, kpath);
#endif
			break;
		}

		case GRAPHENE_MCAST_PORT: {
			struct socket *sock;
			struct sock *sk;
			struct inet_sock *inet;
			struct file *file;
			unsigned short port;

			rv = sock_create(AF_INET, SOCK_DGRAM, 0, &sock);
			if (rv)
				goto err;

			file = sock_alloc_file(sock, 0, NULL);
			if (unlikely(IS_ERR(file))) {
				sock_release(sock);
				rv = PTR_ERR(file);
				goto err;
			}

			sk = sock->sk;
			lock_sock(sk);
			inet = inet_sk(sk);
			sk->sk_reuse = SK_CAN_REUSE;
			if (sk->sk_prot->get_port(sk, 0)) {
				release_sock(sk);
				sock_release(sock);
				rv = -EAGAIN;
				goto err;
			}
			port = inet->inet_sport = htons(inet->inet_num);
			release_sock(sk);
			gi->gi_mcast_port = port;
			gi->gi_mcast_sock = file;
			port = ntohs(port);

			rv = copy_to_user((void *) ptmp.value, &port,
					  sizeof(unsigned short));
			if (rv) {
				rv = -EFAULT;
				goto err;
			}

#ifdef GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d MCAST PORT %d\n",
			       current->pid, port);
#endif
			break;
		}

		case GRAPHENE_NET_RULE: {
			struct graphene_net_rule nr;

			rv = copy_from_user(&nr, ptmp.value,
					    sizeof(struct graphene_net_rule));
			if (rv) {
				rv = -EFAULT;
				goto err;
			}

			rv = set_net_rule(&nr, gi, flags & GRAPHENE_NET_BIND);
			if (rv < 0)
				goto err;

			break;
		}

		case GRAPHENE_FS_PATH:
			rv = strncpy_from_user(kname, ptmp.value, PATH_MAX);
			if (rv < 0)
				goto err;

			p = kmalloc(sizeof(struct graphene_path),
				    GFP_KERNEL);
			rv = -ENOMEM;
			if (!p)
				goto err;

			new = kmalloc(sizeof(*new), GFP_KERNEL);
			if (!new) {
				kfree(p);
				goto err;
			}

			new->name = kname;
			p->path = new;

			tmp = __getname();
			if (!tmp) {
				kfree(p);
				goto err;
			}
			kname = (char *) tmp;

#ifdef GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d PATH %s%s\n",
			       current->pid, p->path->name,
			       type == GRAPHENE_FS_PATH ? "" : " (recursive)");
#endif
			p->type = flags;
			INIT_LIST_HEAD(&p->list);
			list_add_tail(&p->list,
				      (flags & GRAPHENE_FS_RECURSIVE) ?
				      &gi->gi_rpaths : &gi->gi_paths);
			break;
		}
	}

	if (!file->private_data) {
		file->private_data = gi;
		printk(KERN_INFO "Graphene: PID %d registered\n",
		       current->pid);
	} else {
		if ((rv = update_sandbox(file, gi)) < 0) {
			printk(KERN_INFO
			       "Graphene: PID %d cannot be updated (%d)\n",
			       current->pid, rv);
			goto err;
		}

		printk(KERN_INFO "Graphene: PID %d updated\n",
		       current->pid);
	}
	rv = 0;
	goto out;
err:
	drop_graphene_info(gi);
out:
	if (tmp)
		__putname(tmp);
	return rv;
}

static int do_close_sock(struct graphene_info *gi, struct socket *sock,
			 int close_unix)
{
	struct sock *sk = sock->sk;
	struct sockaddr_storage address;
	struct sockaddr *addr = (void *) &address;
	struct inet_sock *inet;
	int len, err;

	if (!sk)
		return 0;

	if (sk->sk_family == PF_UNIX)
		return close_unix ? -EPERM : 0;

	inet = inet_sk(sk);
	if (inet->inet_dport) {
		err = sock->ops->getname(sock, addr, &len, 1);
		if (err)
			return err;

		/* give it a chance, check if it match one of the peers */
		err = __common_net_perm(gi, OP_CONNECT, sock, addr, len);
		if (!err)
			return 0;
	}

	if (!inet->inet_num)
		return 0;

	err = sock->ops->getname(sock, addr, &len, 0);
	if (err)
		return err;

	return __common_net_perm(gi, OP_BIND, sock, addr, len);
}

static int do_close_fds(struct graphene_info *gi, struct files_struct *files,
			int close_unix)
{
	struct fdtable *fdt;
	struct filename *tmp;
	const char *path;
	int fd, i = 0;

	rcu_read_lock();
	fdt = files_fdtable(files);
	rcu_read_unlock();
	for (;;) {
		unsigned long set;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		fd = i * BITS_PER_LONG;
#else
		fd = i * __NFDBITS;
#endif
		if (fd >= fdt->max_fds)
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		set = fdt->open_fds[i++];
#else
		set = fdt->open_fds->fds_bits[i++];
#endif
		for ( ; set ; fd++, set >>= 1) {
			struct socket *sock = NULL;
			struct file *file;
			int err;

			if (!(set & 1))
				continue;

			file = xchg(&fdt->fd[fd], NULL);
			if (!file)
				continue;

			if (get_pipe_info(file))
				goto deny;

			sock = sock_from_file(file, &err);
			if (sock) {
				err = do_close_sock(gi, sock, close_unix);
				if (!err)
					goto allow;
				goto deny;
			}

			tmp =__getname();
			err = -ENOMEM;
			if (unlikely(!tmp))
				goto deny;

			path = d_path(&file->f_path, (char *) tmp, PATH_MAX);
    			if (IS_ERR(path)) {
				__putname(tmp);
				err = PTR_ERR(path);
				goto deny;
			}

			err = __common_file_perm(gi, path, OP_OPEN,
						 MAY_READ|MAY_WRITE);
			__putname(tmp);
			if (err)
				goto deny;

allow:
			xchg(&fdt->fd[fd], file);
			continue;
deny:
			filp_close(file, files);
			cond_resched();
		}
	}
	return 0;
}

static
int net_check (int family,
	       int flags1, struct graphene_net_addr * addr1,
	       int flags2, struct graphene_net_addr * addr2)
{
	if (flags2 & ADDR_ANY)
		goto port;
	if (flags1 & ADDR_ANY)
		goto port;
	
	switch (family) {
	case AF_INET:
		if (memcmp(&addr1->addr.sin_addr,
			   &addr2->addr.sin_addr,
			   sizeof(struct in_addr)))
			return -EPERM;
		break;
	case AF_INET6:
		if (memcmp(&addr1->addr.sin6_addr,
			   &addr2->addr.sin6_addr,
			   sizeof(struct in6_addr)))
			return -EPERM;
		break;
	}

port:
	if (flags2 & PORT_ANY)
		return 0;
	if (flags1 & PORT_ANY)
		return 0;

	if (addr1->port_begin < addr2->port_begin ||
	    addr1->port_end > addr2->port_end)
		return -EPERM;

	return 0;
}

static int net_check_fds(struct graphene_net *n, struct files_struct *files)
{
	struct fdtable *fdt;
	int fd, i = 0;

	rcu_read_lock();
	fdt = files_fdtable(files);
	for (;;) {
		unsigned long set;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		fd = i * BITS_PER_LONG;
#else
		fd = i * __NFDBITS;
#endif
		if (fd >= fdt->max_fds)
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		set = fdt->open_fds[i++];
#else
		set = fdt->open_fds->fds_bits[i++];
#endif
		for ( ; set ; fd++, set >>= 1) {
			struct file *file;
			struct socket *sock;
			struct sock *sk;
			struct inet_sock *inet;
			struct sockaddr_storage address;
			struct sockaddr *addr = (void *) &address;
			int len, err;

			if (!(set & 1))
				continue;

			file = rcu_dereference_raw(fdt->fd[fd]);
			if (!file)
				continue;

			sock = sock_from_file(file, &err);
			if (!sock)
				continue;

			if (!(sk = sock->sk) || sk->sk_family != n->family)
				continue;

			inet = inet_sk(sk);
			if (!inet->inet_dport)
				continue;

			err = sock->ops->getname(sock, addr, &len, 1);
			if (err)
				continue;

			if (!net_cmp(n->family, false, false,
				     &n->addr, addr, len)) {
				rcu_read_unlock();
				return 1;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

static int update_sandbox(struct file *file, struct graphene_info *new)
{
	struct graphene_info *gi = (void *) file->private_data;
	struct graphene_path *p;
	struct graphene_net *n1, *n2;
	int close_unix = 0;

	list_for_each_entry(p, &new->gi_paths, list) {
		u32 mask = 0;
		if (p->type & GRAPHENE_FS_READ)
			mask |= MAY_READ;
		if (p->type & GRAPHENE_FS_WRITE)
			mask |= MAY_WRITE;
		printk(KERN_INFO "Graphene: PID %d CHECK RULE %s\n",
		       current->pid, p->path->name);
		if (__common_file_perm(gi, p->path->name, OP_OPEN, mask) < 0)
			return -EPERM;
	}

	list_for_each_entry(n1, &new->gi_binds, list) {
		bool accepted = false;
		print_net_rule(KERN_INFO
			       "Graphene: PID %d CHECK RULE BIND %s\n",
			       n1);

		list_for_each_entry(n2, &gi->gi_binds, list) {
			if (n1->family != n2->family)
				continue;

			if (net_check(n1->family,
				      n1->flags, &n1->addr,
				      n2->flags, &n2->addr) < 0)
				continue;

			accepted = true;
			print_net_rule(KERN_INFO
				       "Graphene: PID %d ALLOW BIND %s\n",
				       n1);
			break;
		}

		if (!accepted) {
			print_net_rule(KERN_INFO
				       "Graphene: PID %d DENY BIND %s\n",
				       n1);
			return -EPERM;
		}
	}

	list_for_each_entry(n1, &new->gi_peers, list) {
		bool accepted = false;
		print_net_rule(KERN_INFO
			       "Graphene: PID %d CHECK RULE CONNECT %s\n",
			       n1);

		list_for_each_entry(n2, &gi->gi_peers, list) {
			if (n1->family != n2->family)
				continue;

			if (net_check(n1->family,
				      n1->flags, &n1->addr,
				      n2->flags, &n2->addr) < 0)
				continue;

			accepted = true;
			print_net_rule(KERN_INFO
				       "Graphene: PID %d ALLOW CONNECT %s\n",
				       n1);
			break;
		}

		if (!accepted && !(n1->flags & (ADDR_ANY|PORT_ANY)) &&
		    net_check_fds(n1, current->files))
			accepted = true;

		if (!accepted) {
			print_net_rule(KERN_INFO
				       "Graphene: PID %d DENY CONNECT %s\n",
				       n1);
			return -EPERM;
		}
	}

	if (!new->gi_unix[1] && gi->gi_unix[1])
		memcpy(new->gi_unix, gi->gi_unix, sizeof(gi->gi_unix));

	if (!new->gi_mcast_port)
		new->gi_mcast_port = gi->gi_mcast_port;

	if (!new->gi_mcast_sock && gi->gi_mcast_sock) {
		atomic_long_inc(&gi->gi_mcast_sock->f_count);
		new->gi_mcast_sock = gi->gi_mcast_sock;
	}

	do_close_fds(new, current->files, close_unix);
	file->private_data = new;
	put_graphene_info(gi);
	return 0;
}
