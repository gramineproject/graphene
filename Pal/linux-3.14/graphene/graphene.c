/*
 *  linux/graphene/graphene.c
 *
 *  Copyright (C) 2013-, Chia-Che Tsai, Bhushan Jain and Donald Porter
 *
 *  Manage the graphene information and security policies.
 */

#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/un.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp_states.h>
#include <linux/pipe_fs_i.h>
#include <../fs/internal.h>
#include <../security/apparmor/include/audit.h>
#include "graphene.h"
#include "graphene-ipc.h"

static struct list_head unix_list = LIST_HEAD_INIT(unix_list);
static DEFINE_SPINLOCK(unix_list_lock);

static atomic_t gipc_session;

static int add_graphene_unix(struct graphene_unix *u)
{
	struct graphene_unix *tmp;
	int err = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(tmp, &unix_list, list) {
		if (u->root.mnt) {
			if (!tmp->root.mnt)
				continue;
			if (!path_equal(&tmp->root, &u->root))
				continue;
		}
		if (u->prefix.len) {
			int len;
			if (!tmp->prefix.len)
				continue;
			len = u->prefix.len < tmp->prefix.len ?
			      u->prefix.len : tmp->prefix.len;
			if (!strncmp(u->prefix.name, tmp->prefix.name, len)) {
				err = -EACCES;
				break;
			}
		}
	}

	if (!err) {
		spin_lock(&unix_list_lock);
		list_add_tail_rcu(&u->list, &unix_list);
		spin_unlock(&unix_list_lock);
	}

	rcu_read_unlock();
	return err;;
}

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

	if (info->gi_unix) {
		struct graphene_unix *u = info->gi_unix;
		if (!atomic_dec_return(&u->count)) {
			spin_lock(&unix_list_lock);
			if (!list_empty(&u->list)) {
				list_del_rcu(&u->list);
				spin_unlock(&unix_list_lock);
				synchronize_rcu();
			}
			if (u->root.mnt)
				path_put(&u->root);
			if (u->prefix.len)
				kfree(u->prefix.name);
			kfree(u);
		}
	}

	for (i = 0 ; i < 3 ; i++)
		if (info->gi_console[i].mnt)
			path_put(&info->gi_console[i]);

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

	if (!inode)
		return -EINVAL;
	if (!inode->i_fop || !inode->i_fop->read)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
# define DEFINE_PATH_BUFFER(fn, kpath, max) struct filename *fn; char *kpath; int max;
#else
# define DEFINE_PATH_BUFFER(fn, kpath, max) char * kpath; int max;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
# define GET_PATH_BUFFER(fn, kpath, max)				\
	fn = __getname();						\
	kpath = (char *) fn + sizeof(*fn);				\
	max = PATH_MAX - sizeof(*fn);
#else
# define GET_PATH_BUFFER(fn, kpath, max)				\
	kpath = __getname();						\
	max = PATH_MAX;
#endif


#define DEFINE_PATH(dp, path, fn, kpath, max)				\
	DEFINE_PATH_BUFFER(fn, kpath, max)				\
	char *dp;							\
	GET_PATH_BUFFER(fn, kpath, max)					\
	dp = d_path(path, kpath, max);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
# define PUT_PATH_BUFFER(fn, kpath) final_putname(fn);
#else
# define PUT_PATH_BUFFER(fn, kpath) putname(kpath);
#endif

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
			DEFINE_PATH(dp, &file->f_path, fn, kpath, max)
			if (!IS_ERR(dp))
				printk(KERN_INFO "Graphene: PID %d MAP FILE %s"
				       " OFF 0x%08lx AT 0x%016lx\n",
				       current->pid, dp,
				       pgoff * PAGE_SIZE, addr);
			PUT_PATH_BUFFER(fn, kpath)
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

#ifdef CONFIG_GRAPHENE_DEBUG
static void print_path(const char * fmt, struct path *path)
{
	DEFINE_PATH(dp, path, fn, kpath, max)
	printk(fmt, current->pid, IS_ERR(dp) ? "(unknown)" : dp);
	PUT_PATH_BUFFER(fn, kpath)
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
		return -EACCES;
	}

	if (!gi->gi_libaddr)
		goto accepted;

	file->f_op = &graphene_lib_operations;
accepted:
	print_path(KERN_INFO "Graphene: ALLOW EXEC PID %d PATH %s\n",
		   &file->f_path);
	return 0;
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
			return -EACCES;
	}

	if (mask & (MAY_WRITE|MAY_APPEND|
		    AA_MAY_CREATE|AA_MAY_DELETE|AA_MAY_META_WRITE|
		    AA_MAY_CHMOD|AA_MAY_CHOWN)) {
		if (!(gp->type & GRAPHENE_FS_WRITE))
			return -EACCES;
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

	if (op == OP_OPEN) {
		int minor = iminor(path.dentry->d_inode);
		if (minor == GRAPHENE_MINOR)
			goto out;
		if (minor == GIPC_MINOR)
			goto out;
	}

	rcu_read_lock();

	for (i = 0 ; i < 3 ; i++) {
		if (!gi->gi_console[i].mnt)
			continue;
		if (path_equal(&gi->gi_console[i], &path))
			goto out;
	}

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

		if (gi->gi_unix && gi->gi_unix->root.mnt) {
			struct graphene_unix *u = gi->gi_unix;

			if (path_equal(&path, &u->root)) {
				rv = 0;
				if (op == OP_MKNOD)
					goto out_root;
				if (op == OP_UNLINK) {
					if (!u->prefix.len)
						goto out_root;
					if (last.len) {
						int len = u->prefix.len;
						if (last.len < len)
							len = last.len;
						if (!strncmp(last.name,
							     u->prefix.name,
							     len))
							goto out_root;
					}
				}
				break;
			}
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

	rv = -EACCES;
out_root:
	path_put(&root);
out:
	rcu_read_unlock();
	path_put(&path);
	if (rv >= 0) {
		rv = 0;
		print_path(KERN_INFO "Graphene: ALLOW PID %d PATH %s\n", target);
	} else {
		print_path(KERN_INFO "Graphene: DENY PID %d PATH %s\n", target);
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
	const char *path, *sun_path;
	struct nameidata nd;
	struct path *p = NULL;
	int err = 0;

	if (!gi->gi_unix)
		return -EPERM;

	path = sun_path = ((struct sockaddr_un *) address)->sun_path;

	if (gi->gi_unix->root.mnt) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		struct path parent;

		err = kern_path(path, LOOKUP_FOLLOW, &nd.path);
		if (!err)
			return err;

		p = &nd.path;

		err = vfs_path_lookup(nd.path.dentry, nd.path.mnt, "..", 0,
				      &parent);
		if (!err)
			goto denied;

		if (!path_equal(&gi->gi_unix->root, &parent))
			goto denied;

		path_put(&parent);
		path = nd.path.dentry->d_name.name;
#else
		err = kern_path_parent(path, &nd);
		if (!err)
			return err;

		path_put(&nd.path);
		path = nd.last.name;

		if (!path_equal(&gi->gi_unix->root, &nd.path))
			goto denied;

#endif
	}

	if (gi->gi_unix->prefix.len &&
	    memcmp(path, gi->gi_unix->prefix.name,
		   gi->gi_unix->prefix.len))
		err = -EPERM;

	if (p)
		path_put(p);

	if (!err)
		return 0;

denied:
#ifdef CONFIG_GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: DENY PID %d SOCKET %s\n",
	       current->pid, sun_path);
#endif
	if (p)
		path_put(p);
	return -EPERM;
}

static int net_cmp(int family, int addr_any, int port_any,
		   struct graphene_net_addr *ga,
		   struct sockaddr *addr, int addrlen)
{
	switch(family) {
	case AF_INET: {
		struct sockaddr_in *a = (void *) addr;

		if (!addr_any) {
			if (a->sin_addr.s_addr != ga->addr.sin_addr.s_addr)
				return -EPERM;
		}
		if (!port_any) {
			unsigned short port = ntohs(a->sin_port);
			if (!(port >= ga->port_begin && port <= ga->port_end))
				return -EPERM;
		}

		break;
	}
#ifdef CONFIG_IPV6
	case AF_INET6: {
		struct sockaddr_in6 *a6 = (void *) addr;

		if (!addr_any) {
			if (memcmp(&a6->sin6_addr, &ga->addr.sin6_addr,
				   sizeof(struct in6_addr)))
				return -EPERM;
		}
		if (!port_any) {
			unsigned short port = ntohs(a6->sin6_port);
			if (!(port >= ga->port_begin && port <= ga->port_end))
				return -EPERM;
		}

		break;
	}
#endif
	}

	return 0;
}

#ifdef CONFIG_GRAPHENE_DEBUG
static void print_net(int allow, int family, int op,
		      struct sockaddr *local_addr, int local_addrlen,
		      struct sockaddr *peer_addr, int peer_addrlen)
{
	const char *allow_str = allow ? "ALLOW" : "DENY";
	const char *op_str = "";
	int print_peer = (op == OP_CONNECT || op == OP_SENDMSG);

	switch(op) {
		case OP_BIND:		op_str = "BIND";	break;
		case OP_LISTEN:		op_str = "LISTEN";	break;
		case OP_CONNECT:	op_str = "CONNECT";	break;
		case OP_SENDMSG:	op_str = "SENDMSG";	break;
		case OP_RECVMSG:	op_str = "RECVMSG";	break;
	}

	if (family == AF_INET) {
		struct sockaddr_in *la = (void *) local_addr;
		u8 *a1 = (u8 *) &la->sin_addr.s_addr;
		struct sockaddr_in *pa = (void *) peer_addr;
		u8 *a2 = (u8 *) &pa->sin_addr.s_addr;

		if (print_peer && peer_addr) {
			printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
			       "%d.%d.%d.%d:%d:%d.%d.%d.%d:%d\n",
			       allow_str, op_str, current->pid,
			       a1[0], a1[1], a1[2], a1[3], ntohs(la->sin_port),
			       a2[0], a2[1], a2[2], a2[3], ntohs(pa->sin_port));
		} else {
			printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
			       "%d.%d.%d.%d:%d\n",
			       allow_str, op_str, current->pid,
			       a1[0], a1[1], a1[2], a1[3], ntohs(la->sin_port));
		}
	}

#ifdef CONFIG_IPV6
	if (family == AF_INET6) {
		struct sockaddr_in6 *la = (void *) local_addr;
		u16 *a1 = (u16 *) &la->sin6_addr.s6_addr;
		struct sockaddr_in6 *pa = (void *) peer_addr;
		u16 *a2 = (u16 *) &pa->sin6_addr.s6_addr;

		if (print_peer) {
			printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
			       "[%d:%d:%d:%d:%d:%d:%d:%d]:%d:"
			       "[%d.%d.%d.%d:%d:%d:%d:%d]:%d\n",
			       allow_str, op_str, current->pid,
			       a1[0], a1[1], a1[2], a1[3],
			       a1[4], a1[5], a1[6], a1[7], ntohs(la->sin6_port),
			       a2[0], a2[1], a2[2], a2[3],
			       a2[4], a2[5], a2[6], a2[7], ntohs(pa->sin6_port));
		} else {
			printk(KERN_INFO "Graphene: %s %s PID %d SOCKET "
			       "[%d.%d.%d.%d:%d:%d:%d:%d]:%d\n",
			       allow_str, op_str, current->pid,
			       a1[0], a1[1], a1[2], a1[3],
			       a1[4], a1[5], a1[6], a1[7], ntohs(la->sin6_port));
		}
	}
#endif
}
#else
# define print_net(...) do {} while (0)
#endif

/*
 * network rules:
 *    bind:
 *        input addr/port match local addr/port
 *    listen:
 *        local addr/port match local addr/port
 *        allow ANY peer addr/port
 *    connect:
 *        local/remote addr/port match local/remote addr/port
 *    sendmsg:
 *        EITHER stream socket OR no inport addr/port OR
 *        local/remote addr/port match local/remote addr/port
 *    recvmsg:
 *        EITHER stream socket OR connected OR
 *        allow ANY peer addr/port
 */
static
int __common_net_perm(struct graphene_info *gi, int op, struct socket *sock,
		      struct sockaddr *address, int addrlen)
{
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct graphene_net *gn;
	struct sockaddr_storage addrbuf;
	struct sockaddr * local_addr = NULL, * peer_addr = NULL;
	int local_addrlen, peer_addrlen;
	int local_needcmp = 0, peer_needcmp = 0;
	int local_needany = 0, peer_needany = 0;
	int err;

	if (sk->sk_type != SOCK_STREAM && sk->sk_type != SOCK_DGRAM)
		return -EPERM;

#ifdef CONFIG_IPV6
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
#else
	if (sk->sk_family != AF_INET)
#endif
		return -EPERM;

	if (list_empty(&gi->gi_net))
		return -EPERM;

	if (op == OP_LISTEN)
		peer_needany = 1;

	if (op == OP_RECVMSG) {
		if (inet->inet_dport)
			return 0;

		peer_needany = 1;
	}

	if (op == OP_CONNECT || op == OP_SENDMSG) {
		BUG_ON(!address);
		peer_addr = address;
		peer_addrlen = addrlen;
		peer_needcmp = 1;
	}

	if (op == OP_BIND) {
		BUG_ON(!address);
		local_addr = address;
		local_addrlen = addrlen;
		local_needcmp = 1;
		if (sk->sk_type == SOCK_DGRAM)
			peer_needany = 1;
	} else {
		local_addr = (struct sockaddr *) &addrbuf;
		local_needcmp = 1;

		err = sock->ops->getname(sock, local_addr, &local_addrlen, 0);
		if (err < 0)
			return err;
	}

	list_for_each_entry(gn, &gi->gi_net, list) {
		if (gn->family != sk->sk_family)
			continue;

		if (local_needany &&
		    (gn->flags & (LOCAL_ADDR_ANY|LOCAL_PORT_ANY)) !=
		    (LOCAL_ADDR_ANY|LOCAL_PORT_ANY))
			continue;

		if (peer_needany &&
		    (gn->flags & (PEER_ADDR_ANY|PEER_PORT_ANY)) !=
		    (PEER_ADDR_ANY|PEER_PORT_ANY))
			continue;

		if (local_needcmp) {
			err = net_cmp(sk->sk_family, gn->flags & LOCAL_ADDR_ANY,
				      gn->flags & LOCAL_PORT_ANY,
				      &gn->local, local_addr, local_addrlen);
			if (err < 0)
				continue;
		}

		if (peer_needcmp) {
			err = net_cmp(sk->sk_family, gn->flags & PEER_ADDR_ANY,
				      gn->flags & PEER_PORT_ANY,
				      &gn->peer, peer_addr, peer_addrlen);
			if (err < 0)
				continue;
		}

		print_net(1, sk->sk_family, op, local_addr, local_addrlen,
			  peer_addr, peer_addrlen);
		return 0;
	}

	print_net(0, sk->sk_family, op, local_addr, local_addrlen,
		  peer_addr, peer_addrlen);
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
	int i, j, n = 0;
	struct fdtable *fdt = files_fdtable(files);
	j = 0;

	rcu_read_lock();
	fdt = files_fdtable(files);
	rcu_read_unlock();
	for (;;) {
		unsigned long set;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		i = j * BITS_PER_LONG;
#else
		i = j * __NFDBITS;
#endif
		if (i >= fdt->max_fds)
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		set = fdt->open_fds[j++];
#else
		set = fdt->open_fds->fds_bits[j++];
#endif
		for ( ; set ; i++, set >>= 1) {
			struct file *file;
			int k;

			if (!(set & 1))
				continue;

			if (i > 2)
				goto out;

			file = xchg(&fdt->fd[i], NULL);
			if (!file)
				continue;

			for (k = 0 ; k < n ; k++)
				if (path_equal(&file->f_path, &gi->gi_console[k]))
					break;
			if (k == n) {
				path_get(&file->f_path);
				gi->gi_console[n++] = file->f_path;
			}
#ifdef CONFIG_GRAPHENE_DEBUG
			{
				DEFINE_PATH(dp, &file->f_path, fn, kpath, max)
				if (!IS_ERR(dp))
					printk(KERN_INFO "Graphene: "
					       "PID %d CONSOLE %s\n",
					       current->pid, dp);
				PUT_PATH_BUFFER(fn, kpath)
			}
#endif
			xchg(&fdt->fd[i], file);
		}
	}
out:
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
	int len = 0, i;

	for (i = 0; i < 2; i++) {
		unsigned char addr_any = i ? PEER_ADDR_ANY : LOCAL_ADDR_ANY;
		unsigned char port_any = i ? PEER_PORT_ANY : LOCAL_PORT_ANY;
		struct graphene_net_addr *a = i ? &n->peer : &n->local;

		if (i)
			str[len++] = ':';

		switch(n->family) {
		case AF_INET:
			if (n->flags & addr_any) {
				str[len++] = ':';
			} else {
				u8 *ip = (u8 *) &a->addr.sin_addr.s_addr;
				len += snprintf(str + len,
						ADDR_STR_MAX - len,
						"%u.%u.%u.%u:",
						ip[0], ip[1], ip[2], ip[3]);
			}
			break;
#ifdef CONFIG_IPV6
		case AF_INET6:
			if (n->flags & addr_any) {
				str[len++] = '[';
				str[len++] = ']';
				str[len++] = ':';
			} else {
				u16 *ip = (u16 *) &a->addr.sin6_addr.s6_addr;
				len += snprintf(str + len,
						ADDR_STR_MAX - len,
						"[%u:%u:%u:%u:%u:%u:%u:%u]:",
						ip[0], ip[1], ip[2], ip[3],
						ip[4], ip[5], ip[6], ip[7]);
			}
			break;
#endif /* CONFIG_IPV6 */
		}

		if (!(n->flags & port_any)) {
			if (a->port_begin == a->port_end)
				len += snprintf(str + len, ADDR_STR_MAX - len,
						"%u", a->port_begin);
			else
				len += snprintf(str + len, ADDR_STR_MAX - len,
						"%u-%u",
						a->port_begin, a->port_end);
		}
	}

	BUG_ON(len >= ADDR_STR_MAX);
	str[len] = 0;
	printk(fmt, current->pid, str);
}
#else
# define print_net_rule(...) do {} while (0)
#endif

static int set_net_rule(struct graphene_net_policy *np,
			struct graphene_info *gi)
{
	struct graphene_net *n;
	int i;

#ifdef CONFIG_IPV6
	if (np->family != AF_INET && np->family != AF_INET6)
#else
	if (np->family != AF_INET)
#endif
		return -EINVAL;

	n = kmalloc(sizeof(struct graphene_net), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->family  = np->family;
	n->flags   = 0;
	n->local   = np->local;
	n->peer    = np->peer;

	for (i = 0; i < 2; i++) {
		unsigned char addr_any = i ? PEER_ADDR_ANY : LOCAL_ADDR_ANY;
		unsigned char port_any = i ? PEER_PORT_ANY : LOCAL_PORT_ANY;
		struct graphene_net_addr *a = i ? &n->peer : &n->local;

		switch(n->family) {
		case AF_INET:
			if (!a->addr.sin_addr.s_addr)
				n->flags |= addr_any;
			break;
#ifdef CONFIG_IPV6
		case AF_INET6:
			if (!memcmp(&a->addr.sin6_addr.s6_addr, &in6addr_any, 16))
				n->flags |= addr_any;
			break;
#endif /* CONFIG_IPV6 */
		}

		if (a->port_begin == 0 && a->port_end == 65535)
			n->flags |= port_any;
	}

	INIT_LIST_HEAD(&n->list);
	list_add_tail(&n->list, &gi->gi_net);
	print_net_rule(KERN_INFO "Graphene: PID %d NET RULE %s\n", n);
	return 0;
}

u32 gipc_get_session(struct task_struct *tsk)
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
	struct graphene_unix *u;
	int i, rv = 0;
	DEFINE_PATH_BUFFER(fn, kpath, max)
#ifdef CONFIG_GRAPHENE_DEBUG
	char *dp;
#endif

	rv = copy_from_user(&npolicies, &gpolicies->npolicies, sizeof(int));
	if (rv < 0)
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

	GET_PATH_BUFFER(fn, kpath, max)
	memset(gi, 0, sizeof(struct graphene_info));
	INIT_LIST_HEAD(&gi->gi_paths);
	INIT_LIST_HEAD(&gi->gi_rpaths);
	INIT_LIST_HEAD(&gi->gi_net);
	gi->gi_gipc_session = atomic_inc_return(&gipc_session);

#ifdef CONFIG_GRAPHENE_DEBUG
	printk(KERN_INFO "Graphene: PID %d GIPC SESSION %u\n",
	       current_tsk->pid, gi->gi_gipc_session);
#endif

	for (i = 0 ; i < npolicies ; i++) {
		int type, flags;
		rv = copy_from_user(&ptmp, policies + i,
				    sizeof(struct graphene_user_policy));
		if (rv < 0)
			goto err;

		if (!ptmp.value) {
			rv = -EINVAL;
			goto err;
		}

		type = ptmp.type & ~(GRAPHENE_FS_READ | GRAPHENE_FS_WRITE);
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

		case GRAPHENE_UNIX_ROOT:
			rv = strncpy_from_user(kpath, ptmp.value, max);
			if (rv < 0)
				goto err;

			u = gi->gi_unix;
			if (!u) {
				u = kmalloc(sizeof(struct graphene_unix),
				            GFP_KERNEL);
				if (!u) {
					rv = -ENOMEM;
					goto err;
				}

				u->root.mnt = NULL;
				u->prefix.len = 0;
				atomic_set(&u->count, 1);
				INIT_LIST_HEAD(&u->list);
				gi->gi_unix = u;
			}
			if (u && u->root.mnt)
				path_put(&u->root);

			rv = kern_path(kpath, LOOKUP_FOLLOW, &u->root);
			if (rv)
				goto err;

#ifdef CONFIG_GRAPHENE_DEBUG
			dp = d_path(&u->root, kpath, max);
			if (IS_ERR(dp)) {
				rv = -EINVAL;
				goto err;
			}
			printk(KERN_INFO "Graphene: PID %d UNIX ROOT %s\n",
			       current_tsk->pid, dp);
#endif
			break;

		case GRAPHENE_UNIX_PREFIX: {
			char * prefix;

			rv = strncpy_from_user(kpath, ptmp.value, max);
			if (rv < 0)
				goto err;

			u = gi->gi_unix;
			if (!u) {
				u = kmalloc(sizeof(struct graphene_unix),
				            GFP_KERNEL);
				if (!u) {
					rv = -ENOMEM;
					goto err;
				}

				u->root.mnt = NULL;
				u->prefix.len = 0;
				atomic_set(&u->count, 1);
				INIT_LIST_HEAD(&u->list);
				gi->gi_unix = u;
			}
			if (u && u->prefix.len)
				kfree(&u->prefix.name);

			prefix = kmalloc(rv + 1, GFP_KERNEL);
			if (!prefix) {
				rv = -ENOMEM;
				goto err;
			}

			memcpy(prefix, kpath, rv + 1);
			u->prefix.len = rv;
			u->prefix.name = prefix;

#ifdef CONFIG_GRAPHENE_DEBUG
			printk(KERN_INFO "Graphene: PID %d UNIX PREFIX %s\n",
			       current_tsk->pid, kpath);
#endif
			break;
		}

		case GRAPHENE_NET_RULE: {
			struct graphene_net_policy np;

			rv = copy_from_user(&np, ptmp.value,
					    sizeof(struct graphene_net_policy));
			if (rv < 0)
				goto err;

			rv = set_net_rule(&np, gi);
			if (rv < 0)
				goto err;

			break;
		}

		case GRAPHENE_FS_PATH:
		case GRAPHENE_FS_RECURSIVE:
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
				      type == GRAPHENE_FS_PATH ?
				      &gi->gi_paths : &gi->gi_rpaths);
			break;
		}
	}

	if (!current_tsk->graphene) {
		struct graphene_struct *gs;

		if (gi->gi_unix) {
			rv = add_graphene_unix(gi->gi_unix);
			if (rv < 0)
				goto err;
		}

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
	PUT_PATH_BUFFER(fn, kpath)
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
		if (err < 0)
			return err;

		err = __common_net_perm(gi, OP_CONNECT, sock, addr, len);
		if (err < 0)
			return err;

		return 0;
	}

	if (!inet->inet_num)
		return 0;

	if (sk->sk_state == TCP_LISTEN) {
		err = __common_net_perm(gi, OP_LISTEN, sock, NULL, 0);
	} else {
		err = sock->ops->getname(sock, addr, &len, 0);
		if (err < 0)
			return err;

		err = __common_net_perm(gi, OP_BIND, sock, addr, len);
	}

	return err;
}

static int do_close_fds(struct graphene_info *gi, struct files_struct *files,
			int close_unix)
{
	int i, j;
	struct fdtable *fdt = files_fdtable(files);
	j = 0;

	rcu_read_lock();
	fdt = files_fdtable(files);
	rcu_read_unlock();
	for (;;) {
		unsigned long set;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		i = j * BITS_PER_LONG;
#else
		i = j * __NFDBITS;
#endif
		if (i >= fdt->max_fds)
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
		set = fdt->open_fds[j++];
#else
		set = fdt->open_fds->fds_bits[j++];
#endif
		for ( ; set ; i++, set >>= 1) {
			struct socket *sock = NULL;
			struct file *file;
			int err;

			if (!(set & 1))
				continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
			sock = sockfd_lookup(i, &err);
#endif

			file = xchg(&fdt->fd[i], NULL);
			if (!file)
				continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
			sock = sock_from_file(file, &err);
#endif

			if (sock) {
				err = do_close_sock(gi, sock, close_unix);
				if (!err)
					goto allow;
				goto deny;
			}

			if (get_pipe_info(file))
				goto deny;

			err = __common_perm(gi, OP_OPEN, &file->f_path,
					    aa_map_file_to_perms(file));

			if (!err) {
allow:
				xchg(&fdt->fd[i], file);
				continue;
			}

deny:
			filp_close(file, files);
			cond_resched();
		}
	}
	return 0;
}

static
int net_check (int family, int addr_any, int port_any,
	       int flags1, struct graphene_net_addr * addr1,
	       int flags2, struct graphene_net_addr * addr2)
{
	if (flags2 & addr_any)
		goto port;
	if (flags1 & addr_any)
		goto port;
	
	switch (family) {
	case AF_INET:
		if (memcmp(&addr1->addr.sin_addr,
			   &addr2->addr.sin_addr,
			   sizeof(struct in_addr)))
			return -EACCES;
		break;
	case AF_INET6:
		if (memcmp(&addr1->addr.sin6_addr,
			   &addr2->addr.sin6_addr,
			   sizeof(struct in6_addr)))
			return -EACCES;
		break;
	}

port:
	if (flags2 & port_any)
		return 0;
	if (flags1 & port_any)
		return 0;

	if (addr1->port_begin < addr2->port_begin ||
	    addr1->port_end > addr2->port_end)
		return -EACCES;

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

	if (new->gi_unix) {
		if (!new->gi_unix->root.mnt &&
		    gi->gi_unix && gi->gi_unix->root.mnt) {
			if (!path_equal(&new->gi_unix->root,
					&gi->gi_unix->root))
				return -EACCES;
			path_get(&gi->gi_unix->root);
			new->gi_unix->root = gi->gi_unix->root;
		}
		if (new->gi_unix->prefix.len) {
			int err = add_graphene_unix(new->gi_unix);
			if (err < 0)
				return err;
		}
		close_unix = 1;
	}

	for (i = 0 ; i < 3 ; i++)
		if (gi->gi_console[i].mnt) {
			path_get(&gi->gi_console[i]);
			new->gi_console[i] = gi->gi_console[i];
		} else {
			new->gi_console[i].mnt = NULL;
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
			return -EACCES;
	}

	list_for_each_entry(n1, &new->gi_net, list) {
		bool accepted = false;
		print_net_rule(KERN_INFO "Graphene: PID %d CHECK RULE %s\n",
			       n1);
		list_for_each_entry(n2, &gi->gi_net, list) {
			if (n1->family != n2->family)
				continue;

			if (net_check(n1->family,
				      LOCAL_ADDR_ANY, LOCAL_PORT_ANY,
				      n1->flags, &n1->local,
				      n2->flags, &n2->local) < 0)
				continue;

			if (net_check(n1->family,
				      PEER_ADDR_ANY, PEER_PORT_ANY,
				      n1->flags, &n1->peer,
				      n2->flags, &n2->peer) < 0)
				continue;

			accepted = true;
			print_net_rule(KERN_INFO "Graphene: PID %d ALLOW %s\n",
				       n1);
			break;
		}

		if (!accepted) {
			print_net_rule(KERN_INFO "Graphene: PID %d DENY %s\n",
				       n1);
			return -EACCES;
		}
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
