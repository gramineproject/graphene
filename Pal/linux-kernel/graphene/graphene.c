/*
 *  linux/graphene/graphene.c
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
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/net.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp_states.h>
#include <linux/pipe_fs_i.h>
#include <../fs/internal.h>
#include <../security/apparmor/include/audit.h>
#include "graphene.h"
#include "graphene-ipc.h"

static atomic64_t unix_prefix_counter	= ATOMIC64_INIT(1);
static atomic64_t gipc_session		= ATOMIC64_INIT(1);;

int dup_graphene_struct(struct task_struct *tsk)
{
	struct graphene_struct *gs, *new;
	struct graphene_info *gi;

	if (!(tsk->graphene))
		return 0;

	if (tsk->group_leader != tsk) {
		atomic_inc(&tsk->graphene->g_count);
		return 0;
	}

	gs = tsk->graphene;
	new = kmalloc(sizeof(struct graphene_struct), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	spin_lock(&gs->g_lock);
	gi = gs->g_info;
	atomic_inc(&gi->gi_count);
	new->g_info = gi;
	spin_unlock(&gs->g_lock);

	atomic_set(&new->g_count, 1);
	spin_lock_init(&new->g_lock);
	tsk->graphene = new;

	return 0;
}

static void drop_graphene_info(struct graphene_info *info)
{
	struct graphene_path *p, *n;
	int i;

	list_for_each_entry_safe(p, n, &info->gi_paths, list) {
		path_put(&p->path);
		kfree(p);
	}

	list_for_each_entry_safe(p, n, &info->gi_rpaths, list) {
		path_put(&p->path);
		kfree(p);
	}

	if (info->gi_libexec.dentry)
		path_put(&info->gi_libexec);

	for (i = 0 ; i < 3 && info->gi_console[i].mnt ; i++)
		path_put(&info->gi_console[i]);

	if (info->gi_mcast_sock)
		fput(info->gi_mcast_sock);

	kfree(info);
}

static void put_graphene_info(struct graphene_info *info)
{
	if (!atomic_dec_return(&info->gi_count))
		drop_graphene_info(info);
}

void put_graphene_struct(struct task_struct *tsk)
{
	struct graphene_struct *gs = tsk->graphene;
	if (gs) {
		tsk->graphene = NULL;
		if (atomic_dec_return(&gs->g_count))
			return;
		put_graphene_info(gs->g_info);
		kfree(gs);
	}
}

static inline
struct graphene_info *get_graphene_info(struct graphene_struct *gs)
{
	struct graphene_info *info;
	if (!gs)
		return NULL;
	rcu_read_lock();
	info = rcu_dereference_check(gs->g_info,
				     lockdep_is_held(&gs->g_lock) ||
				     atomic_read(&gs->g_count) == 1 ||
				     rcu_my_thread_group_empty());
	rcu_read_unlock();
	return info;
}

#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
# define FILE_INODE(file) ((file)->f_inode)
#else
# define FILE_INODE(file) ((file)->f_dentry->d_inode)
#endif

static loff_t graphene_lib_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = FILE_INODE(file);

	if (!inode)
		return -EINVAL;
	if (!inode->i_fop || !inode->i_fop->llseek)
		return -EINVAL;

	return inode->i_fop->llseek(file, offset, origin);
}

static ssize_t graphene_lib_read (struct file *file, char __user *buf,
				  size_t len, loff_t *ppos)
{
	struct inode *inode = FILE_INODE(file);
	const struct file_operations *fops;

	if (!inode)
		return -EINVAL;

	fops = fops_get(inode->i_fop);
	if (unlikely(!fops))
		return -EINVAL;

	return inode->i_fop->read(file, buf, len, ppos);
}

static ssize_t graphene_lib_aio_read (struct kiocb *iocb, const struct iovec *iov,
				      unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = FILE_INODE(iocb->ki_filp);

	if (!inode)
		return -EINVAL;
	if (!inode->i_fop || !inode->i_fop->aio_read)
		return -EINVAL;

	return inode->i_fop->aio_read(iocb, iov, nr_segs, pos);
}

static int graphene_lib_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = FILE_INODE(file);

	if (!inode)
		return -EINVAL;
	if (!inode->i_fop || !inode->i_fop->mmap)
		return -EINVAL;

	return inode->i_fop->mmap(file, vma);
}

static int graphene_lib_release(struct inode *inode, struct file *file)
{
	if (!inode)
		return -EINVAL;
	if (!inode->i_fop || !inode->i_fop->release)
		return -EINVAL;
	return inode->i_fop->release(inode, file);
}
#endif

#define DEFINE_PATH_BUFFER(kpath, max) char * kpath; int max;

#define GET_PATH_BUFFER(kpath, max)					\
	kpath = __getname();						\
	max = PATH_MAX;


#define DEFINE_PATH(dp, path, kpath, max)				\
	DEFINE_PATH_BUFFER(kpath, max)					\
	char *dp;							\
	GET_PATH_BUFFER(kpath, max)					\
	dp = d_path(path, kpath, max);

#define PUT_PATH_BUFFER(kpath) __putname(kpath);

#if 0
static unsigned long
graphene_lib_get_area(struct file *file, unsigned long addr, unsigned long len,
		      unsigned long pgoff, unsigned long flags)
{
	struct task_struct *current_tsk = current;
	struct graphene_info *gi = get_graphene_info(current_tsk->graphene);
	struct inode *inode = FILE_INODE(file);
	unsigned long (*get_area) (struct file *, unsigned long, unsigned long,
				   unsigned long, unsigned long);

	if (!inode)
		return -EINVAL;

	if (gi->gi_libaddr) {
		if (!path_equal(&file->f_path, &gi->gi_libexec))
			BUG();

		if (!addr)
			addr = gi->gi_libaddr + pgoff * PAGE_SIZE;

#ifdef CONFIG_GRAPHENE_DEBUG
		{
			DEFINE_PATH(dp, &file->f_path, kpath, max)
			if (!IS_ERR(dp))
				printk(KERN_INFO "Graphene: PID %d MAP FILE %s"
				       " OFF 0x%08lx AT 0x%016lx\n",
				       current->pid, dp,
				       pgoff * PAGE_SIZE, addr);
			PUT_PATH_BUFFER(kpath)
		}
#endif
		return addr;
	}

	get_area = (inode->i_fop && inode->i_fop->get_unmapped_area) ?
		   inode->i_fop->get_unmapped_area :
		   current_tsk->mm->get_unmapped_area;

	return get_area(file, addr, len, pgoff, flags);
}

/* These are file oprations required for execve */
static struct file_operations graphene_lib_operations = {
	.llseek			= graphene_lib_llseek,
	.read			= graphene_lib_read,
	.aio_read		= graphene_lib_aio_read,
	.mmap			= graphene_lib_mmap,
	.get_unmapped_area	= graphene_lib_get_area,
	.release		= graphene_lib_release,
};
#endif

#ifdef CONFIG_GRAPHENE_DEBUG
static void print_path(const char * fmt, struct path *path)
{
	DEFINE_PATH(dp, path, kpath, max)
	if (!IS_ERR(dp))
		printk(fmt, current->pid, IS_ERR(dp) ? "(unknown)" : dp);
	PUT_PATH_BUFFER(kpath)
}
#else
# define print_path(...) do {} while (0)
#endif

int graphene_execve_open(struct file *file)
{
	struct task_struct *current_tsk = current;
	struct graphene_info *gi = get_graphene_info(current_tsk->graphene);

	if (!current_tsk->in_execve)
		BUG();

	if (!path_equal(&file->f_path, &gi->gi_libexec)) {
		print_path(KERN_INFO "Graphene: DENY EXEC PID %d PATH %s\n",
			   &file->f_path);
		return -EPERM;
	}

	if (!gi->gi_libaddr)
		goto accepted;

	//file->f_op = &graphene_lib_operations;
accepted:
	print_path(KERN_INFO "Graphene: ALLOW EXEC PID %d PATH %s\n",
		   &file->f_path);
	return 0;
}

unsigned long
graphene_execve_get_area(struct file *file, unsigned long addr,
			 unsigned long len, unsigned long pgoff,
			 unsigned long flags)
{
	unsigned long (*get_area) (struct file *, unsigned long, unsigned long,
				   unsigned long, unsigned long);

	struct task_struct *current_tsk = current;
	struct graphene_info *gi = get_graphene_info(current_tsk->graphene);

	BUG_ON(!file);

	if (gi->gi_libaddr) {
		if (!addr)
			addr = gi->gi_libaddr + pgoff * PAGE_SIZE;

#ifdef CONFIG_GRAPHENE_DEBUG
		{
			DEFINE_PATH(dp, &file->f_path, kpath, max)
			if (!IS_ERR(dp))
				printk(KERN_INFO "Graphene: PID %d MAP FILE %s"
				       " OFF 0x%08lx AT 0x%016lx\n",
				       current->pid, dp,
				       pgoff * PAGE_SIZE, addr);
			PUT_PATH_BUFFER(kpath)
		}
#endif
		return addr;
	}

	get_area = current_tsk->mm->get_unmapped_area;
	if (file->f_op->get_unmapped_area)
		get_area = file->f_op->get_unmapped_area;

	return get_area(file, addr, len, pgoff, flags);
}

static int graphene_check_path(struct graphene_info *gi, int op, u32 mask,
			       struct path *path, struct graphene_path *gp,
			       int is_recursive)
{
	if (!path_equal(path, &gp->path))
		return 0;

	if (mask & (MAY_READ|MAY_EXEC|MAY_ACCESS|
		    AA_MAY_META_READ|AA_EXEC_MMAP|AA_MAY_LINK)) {
		if (!(gp->type & GRAPHENE_FS_READ))
			return -EPERM;
	}

	if (mask & (MAY_WRITE|MAY_APPEND|
		    AA_MAY_CREATE|AA_MAY_DELETE|AA_MAY_META_WRITE|
		    AA_MAY_CHMOD|AA_MAY_CHOWN)) {
		if (!(gp->type & GRAPHENE_FS_WRITE))
			return -EPERM;
	}

	return 1;
}

static int __common_perm(struct graphene_info *gi, int op, struct path *target,
			 u32 mask)
{
	struct graphene_path *p;
	struct path root, path = *target;
	struct qstr last;
	int rv = 0, i;

	BUG_ON(!path.dentry);
	path_get(&path);

	for (i = 0; i < 3 && gi->gi_console[i].mnt; i++)
		if (path_equal(target, &gi->gi_console[i]))
			goto out;

	if (op == OP_OPEN) {
		int minor = iminor(path.dentry->d_inode);
		if (minor == GRAPHENE_MINOR)
			goto out;
		if (minor == GIPC_MINOR)
			goto out;
	}

	rcu_read_lock();

	list_for_each_entry_rcu(p, &gi->gi_paths, list) {
		rv = graphene_check_path(gi, op, mask, &path, p, 0);
		if (rv)
			goto out;
	}

	if (gi->gi_libexec.mnt && path_equal(&path, &gi->gi_libexec)) {
		rv = 0;
		goto out;
	}

	get_fs_root(current->fs, &root);
	last.len = 0;

	while (!path_equal(&path, &root)) {
		int is_recursive = 0;

		list_for_each_entry_rcu(p, &gi->gi_rpaths, list) {
			rv = graphene_check_path(gi, op, mask, &path, p,
						 is_recursive);
			if (rv)
				goto out_root;
		}

		last = path.dentry->d_name;
		while(1) {
			struct dentry *old = path.dentry;

			if (path_equal(&path, &root))
				break;

			if (path.dentry != path.mnt->mnt_root) {
				path.dentry = dget_parent(path.dentry);
				dput(old);
				break;
			}

			if (!follow_up(&path))
				break;
		}
		is_recursive = 1;
	}

	rv = -EPERM;
out_root:
	path_put(&root);
out:
	rcu_read_unlock();
	path_put(&path);
	if (rv >= 0) {
		rv = 0;
		print_path(KERN_INFO "Graphene: ALLOW PID %d PATH %s\n",
			   target);
	} else {
		print_path(KERN_INFO "Graphene: DENY PID %d PATH %s\n",
			   target);
	}
	return rv;
}

int graphene_common_perm(int op, struct path *path, u32 mask)
{
	struct graphene_info *gi = get_graphene_info(current->graphene);

	if (!gi)
		return 0;

	return __common_perm(gi, op, path, mask);
}

static int __unix_perm(struct sockaddr *address, int addrlen)
{
	struct graphene_info *gi = get_graphene_info(current->graphene);
	const char * sun_path =
		((struct sockaddr_un *) address)->sun_path;

	if (!gi->gi_unix[1])
		return -EPERM;

	if (!memcmp(sun_path, gi->gi_unix, sizeof(gi->gi_unix)))
		return 0;

#ifdef CONFIG_GRAPHENE_DEBUG
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

#ifdef CONFIG_GRAPHENE_DEBUG
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
 *    listen:
 *        always allow
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

int graphene_socket_bind(struct socket *sock,
			 struct sockaddr *address, int addrlen)
{
	if (GRAPHENE_ENABLED()) {
		struct graphene_info *gi = get_graphene_info(current->graphene);

		if (!sock || !sock->sk)
			return 0;

		if (sock->sk->sk_family == PF_UNIX) {
			if (sock->sk->sk_type != SOCK_STREAM)
				return -EPERM;

			return __unix_perm(address, addrlen);
		}

		return __common_net_perm(gi, OP_BIND, sock, address, addrlen);
	}
	return 0;
}

int graphene_socket_listen(struct socket *sock, int backlog)
{
	if (GRAPHENE_ENABLED()) {
		struct graphene_info *gi = get_graphene_info(current->graphene);

		if (!sock || !sock->sk || sock->sk->sk_family == PF_UNIX)
			return 0;

		return __common_net_perm(gi, OP_LISTEN, sock, NULL, 0);
	}
	return 0;
}

int graphene_socket_connect(struct socket *sock,
			    struct sockaddr *address, int addrlen)
{
	if (GRAPHENE_ENABLED()) {
		struct graphene_info *gi = get_graphene_info(current->graphene);

		if (!sock || !sock->sk)
			return 0;

		if (sock->sk->sk_family == PF_UNIX) {
			if (sock->sk->sk_type != SOCK_STREAM)
				return -EPERM;

			return __unix_perm(address, addrlen);
		}

		return __common_net_perm(gi, OP_CONNECT, sock, address,
					 addrlen);
	}
	return 0;
}

int graphene_socket_sendmsg(struct socket *sock,
			    struct msghdr *msg, int size)
{
	if (GRAPHENE_ENABLED()) {
		struct graphene_info *gi = get_graphene_info(current->graphene);

		if (!sock || !sock->sk || sock->sk->sk_family == PF_UNIX)
			return 0;

		if (sock->sk->sk_type == SOCK_STREAM)
			return 0;

		if (!msg->msg_name)
			return 0;


		return __common_net_perm(gi, OP_SENDMSG, sock,
					 msg->msg_name, msg->msg_namelen);
	}
	return 0;

}

int graphene_socket_recvmsg(struct socket *sock,
			    struct msghdr *msg, int size, int flags)
{
	if (GRAPHENE_ENABLED()) {
		struct graphene_info *gi = get_graphene_info(current->graphene);

		if (!sock || !sock->sk || sock->sk->sk_family == PF_UNIX)
			return 0;

		if (sock->sk->sk_type == SOCK_STREAM)
			return 0;

		return __common_net_perm(gi, OP_RECVMSG, sock, NULL, 0);
	}
	return 0;
}

int graphene_task_kill(struct task_struct *tsk, struct siginfo *info,
		       int sig, u32 secid)
{
	struct task_struct *current_tsk = current;

	if (!current_tsk->graphene)
		return 0;

	if (sig != SIGCONT)
		return -EPERM;

	return (tsk->tgid == current_tsk->tgid) ? 0 : -EPERM;
}

static void get_console(struct graphene_info *gi, struct files_struct *files)
{
	struct fdtable *fdt;
	unsigned long set;
	int fd = 0, n = 0;

	rcu_read_lock();
	fdt = files_fdtable(files);
	rcu_read_unlock();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	set = fdt->open_fds[0];
#else
	set = fdt->open_fds->fds_bits[0];
#endif

	for (; fd < 3 && fd < fdt->max_fds && set ; fd++, set >>= 1) {
		struct file *file;

		if (!(set & 1))
			continue;

		file = ACCESS_ONCE(fdt->fd[fd]);
		if (!file)
			continue;

		path_get(&file->f_path);
		gi->gi_console[n++] = file->f_path;

#ifdef CONFIG_GRAPHENE_DEBUG
		{
			DEFINE_PATH(dp, &file->f_path, kpath, max)
			if (!IS_ERR(dp))
				printk(KERN_INFO "Graphene: "
				       "PID %d CONSOLE %s\n",
				       current->pid, dp);
			PUT_PATH_BUFFER(kpath)
		}
#endif
	}

	for ( ; n < 3 ; n++)
		gi->gi_console[n].mnt = NULL;
}

static int update_graphene(struct task_struct *current_tsk,
			   struct graphene_info *gi);

#ifdef CONFIG_GRAPHENE_DEBUG
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

u64 gipc_get_session(struct task_struct *tsk)
{
	struct graphene_info *gi = get_graphene_info(tsk->graphene);
	return gi ? gi->gi_gipc_session : 0;
}

int set_graphene(struct task_struct *current_tsk,
		 const struct graphene_policies __user *gpolicies)
{
	int npolicies;
	const struct graphene_user_policy __user *policies = gpolicies->policies;
	struct graphene_info *gi;
	struct graphene_user_policy ptmp;
	struct graphene_path *p;
	int i, rv = 0;
	DEFINE_PATH_BUFFER(kpath, max)
#ifdef CONFIG_GRAPHENE_DEBUG
	char *dp;
#endif

	rv = copy_from_user(&npolicies, &gpolicies->npolicies, sizeof(int));
	if (rv)
		return -EFAULT;

	if (npolicies && !policies)
		return -EINVAL;

#ifndef CONFIG_GRAPHENE_ISOLATE
	if (current_tsk->graphene)
		return -EAGAIN;

	if (current_tsk != current_tsk->group_leader)
		return -EPERM;
#endif

	gi = kmalloc(sizeof(struct graphene_info), GFP_KERNEL);
	if (!gi)
		return -ENOMEM;

	GET_PATH_BUFFER(kpath, max)
	memset(gi, 0, sizeof(struct graphene_info));
	INIT_LIST_HEAD(&gi->gi_paths);
	INIT_LIST_HEAD(&gi->gi_rpaths);
	INIT_LIST_HEAD(&gi->gi_binds);
	INIT_LIST_HEAD(&gi->gi_peers);
	gi->gi_gipc_session = atomic64_inc_return(&gipc_session);

#ifdef CONFIG_GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: PID %d GIPC SESSION %llu\n",
	       current_tsk->pid, gi->gi_gipc_session);
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
		case GRAPHENE_LIB_NAME:
			rv = strncpy_from_user(kpath, ptmp.value, max);
			if (rv < 0)
				goto err;

			rv = kern_path(kpath, LOOKUP_FOLLOW, &gi->gi_libexec);
			if (rv)
				goto err;
#ifdef CONFIG_GRAPHENE_DEBUG
			dp = d_path(&gi->gi_libexec, kpath, max);
			if (IS_ERR(dp)) {
				rv = -EINVAL;
				goto err;
			}
			printk(KERN_INFO "Graphene: PID %d LIB NAME %s\n",
			       current_tsk->pid, dp);
#endif
			break;

		case GRAPHENE_LIB_ADDR:
			gi->gi_libaddr = (u64) ptmp.value;
#ifdef CONFIG_GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d LIB ADDR 0x%016llx\n",
			       current_tsk->pid, gi->gi_libaddr);
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

#ifdef CONFIG_GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d UNIX PREFIX %s\n",
			       current_tsk->pid, kpath);
#endif
			break;
		}

		case GRAPHENE_MCAST_PORT: {
			struct socket *sock;
			struct sock *sk;
			struct inet_sock *inet;
			struct file *file;
			unsigned short port;

			rv = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &sock);
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

#ifdef CONFIG_GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d MCAST PORT %d\n",
			       current_tsk->pid, port);
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
			rv = strncpy_from_user(kpath, ptmp.value, max);
			if (rv < 0)
				goto err;

			p = kmalloc(sizeof(struct graphene_path),
				    GFP_KERNEL);
			if (!p) {
				rv = -ENOMEM;
				goto err;
			}

			rv = kern_path(kpath, LOOKUP_FOLLOW, &p->path);
			if (rv) {
				kfree(p);
				goto err;
			}

#ifdef CONFIG_GRAPHENE_DEBUG
			dp = d_path(&p->path, kpath, max);
			if (IS_ERR(dp)) {
				rv = -EINVAL;
				kfree(p);
				goto err;
			}
			printk(KERN_INFO "Graphene: PID %d PATH %s%s\n",
			       current_tsk->pid, dp,
			       type == GRAPHENE_FS_PATH ? "" :
			       " (recursive)");
#endif
			p->type = flags;
			INIT_LIST_HEAD(&p->list);
			list_add_tail(&p->list,
				      (flags & GRAPHENE_FS_RECURSIVE) ?
				      &gi->gi_rpaths : &gi->gi_paths);
			break;
		}
	}

	if (!current_tsk->graphene) {
		struct graphene_struct *gs;
		get_console(gi, current_tsk->files);

		gs = kmalloc(sizeof(struct graphene_struct), GFP_KERNEL);
		if (!gs) {
			rv = -ENOMEM;
			goto err;
		}

		atomic_set(&gs->g_count, 1);
		gs->g_info = gi;
		spin_lock_init(&gs->g_lock);
		current_tsk->graphene = gs;
		printk(KERN_INFO "Graphene: PID %d registered\n",
		       current_tsk->pid);
	}
#ifdef CONFIG_GRAPHENE_ISOLATE
	else {
		if ((rv = update_graphene(current_tsk, gi)) < 0) {
			printk(KERN_INFO "Graphene: PID %d cannot be updated (%d)\n",
			       current_tsk->pid, rv);
			goto err;
		}

		printk(KERN_INFO "Graphene: PID %d updated\n",
		       current_tsk->pid);
	}
#endif
	rv = 0;
	goto out;
err:
	drop_graphene_info(gi);
out:
	PUT_PATH_BUFFER(kpath)
	return rv;
}

#ifdef CONFIG_GRAPHENE_ISOLATE
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

			err = __common_perm(gi, OP_OPEN, &file->f_path,
					    aa_map_file_to_perms(file));
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

static int update_graphene(struct task_struct *current_tsk,
			   struct graphene_info *new)
{
	struct graphene_struct *gs = current_tsk->graphene;
	struct graphene_info *gi = get_graphene_info(gs);
	struct graphene_path *p;
	struct graphene_net *n1, *n2;
	int i = 0, close_unix = 0;

	for (i = 0 ; i < 3 && gi->gi_console[i].mnt ; i++) {
		path_get(&gi->gi_console[i]);
		new->gi_console[i] = gi->gi_console[i];
	}

	list_for_each_entry(p, &new->gi_paths, list) {
		u32 mask = 0;
		if (p->type & GRAPHENE_FS_READ)
			mask |= MAY_READ;
		if (p->type & GRAPHENE_FS_WRITE)
			mask |= MAY_WRITE;
		print_path(KERN_INFO "Graphene: PID %d CHECK RULE %s\n",
			   &p->path);
		if (__common_perm(gi, OP_OPEN, &p->path, mask) < 0)
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
		    net_check_fds(n1, current_tsk->files))
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

	spin_lock(&gs->g_lock);
	put_graphene_info(gs->g_info);
	gs->g_info = new;
	spin_unlock(&gs->g_lock);

	do_close_fds(new, current_tsk->files, close_unix);
	return 0;
}

#endif /* CONFIG_GRAPHENE_ISOLATE */

static long graphene_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct task_struct *current_tsk = current;

	switch (cmd) {
	case GRAPHENE_SET_TASK:
		return set_graphene(current_tsk,
			(const struct graphene_policies __user *) arg);
	default:
		return -ENOSYS;
	}
}

static struct file_operations graphene_operations = {
	.unlocked_ioctl	= graphene_ioctl,
	.compat_ioctl	= graphene_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice graphene_dev = {
	.minor		= GRAPHENE_MINOR,
	.name		= "graphene",
	.fops		= &graphene_operations,
	.mode		= 0666,
};

static int __init graphene_init(void)
{
	int rv;

	rv = misc_register(&graphene_dev);
	if (rv) {
		printk(KERN_ERR "Graphene error: "
		       "failed to add a char device (rv=%d)\n", rv);
		return rv;
	}

	return 0;
}

device_initcall(graphene_init);
