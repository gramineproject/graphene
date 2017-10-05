#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/kdev_t.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <asm/mman.h>

#include "graphene-rm.h"
#include "graphene-sandbox.h"
#include "ksyms.h"

MODULE_LICENSE("Dual BSD/GPL");

#define GRM_DEBUG	0

#if defined(GRM_DEBUG) && GRM_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
# define GRM_BUG_ON(cond)	BUG_ON(cond)
#else
# define DEBUG(...)
# define GRM_BUG_ON(cond)
#endif

IMPORT_KSYM(do_execve);

long grm_sys_open (struct graphene_info *gi,
		   const char __user *filename, int flags, mode_t mode)
{
	struct filename *tmp;
	struct file *f;
	char *kname;
	int fd, len;

	tmp = __getname();
	if (unlikely(!tmp))
		return -ENOMEM;

	kname = (char *) tmp;
	len = strncpy_from_user(kname, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		__putname(kname);
		return len;
	}

	/* Reference monitor: check "filename" */
	if (gi) {
	}

	f = filp_open(kname, flags, mode);
	if (IS_ERR(f)) {
		__putname(kname);
		return PTR_ERR(f);
	}

	fd = get_unused_fd_flags(flags);
	if (fd >= 0)
		fd_install(fd, f);

	__putname(tmp);
	return fd;
}

long grm_sys_stat (struct graphene_info *gi,
		   const char __user *filename, struct stat __user *statbuf)
{
	struct filename *tmp;
	char *kname;
	struct kstat stat;
	struct stat stattmp;
	int len, error;

	tmp = __getname();
	if (unlikely(!tmp))
		return -ENOMEM;

	kname = (char *) tmp;
	len = strncpy_from_user(kname, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		__putname(kname);
		return len;
	}

	/* Reference monitor: check "filename" */
	if (gi) {
	}

	__putname(kname);

	error = vfs_stat(filename, &stat);
	if (error)
		return error;

	stattmp.st_dev	= old_encode_dev(stat.dev);
	stattmp.st_rdev	= old_encode_dev(stat.rdev);
	stattmp.st_ino	= stat.ino;
	stattmp.st_mode	= stat.mode;
	SET_UID(stattmp.st_uid, from_kuid_munged(current_user_ns(), stat.uid));
	SET_GID(stattmp.st_gid, from_kgid_munged(current_user_ns(), stat.gid));
	stattmp.st_size	= stat.size;
	stattmp.st_atime	= stat.atime.tv_sec;
	stattmp.st_mtime	= stat.mtime.tv_sec;
	stattmp.st_ctime	= stat.ctime.tv_sec;

	return copy_to_user(statbuf, &stattmp, sizeof(stat)) ? -EFAULT : 0;
}

long grm_sys_unlink (struct graphene_info *gi, const char __user *filename)
{
	return -ENOSYS;
}

long grm_sys_rmdir (struct graphene_info *gi, const char __user *filename)
{
	return -ENOSYS;
}

long grm_sys_bind (struct graphene_info *gi,
		   int sockfd, struct sockaddr __user *addr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int error;

	if (addrlen < 0 || addrlen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (addrlen == 0)
		return 0;
	if (copy_from_user(&address, addr, addrlen))
		return -EFAULT;

	/* Reference monitor: check "address" */
	if (gi) {
	}

	sock = sockfd_lookup(sockfd, &error);
	if (!sock)
		return error;

	error = kernel_bind(sock, (struct sockaddr *) &address, addrlen);
	sockfd_put(sock);
	return error;
}

long grm_sys_connect (struct graphene_info *gi,
		      int sockfd, struct sockaddr __user *addr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int error;

	if (addrlen < 0 || addrlen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (addrlen == 0)
		return 0;
	if (copy_from_user(&address, addr, addrlen))
		return -EFAULT;

	/* Reference monitor: check "address" */
	if (gi) {
	}

	sock = sockfd_lookup(sockfd, &error);
	if (!sock)
		return error;

	error = kernel_connect(sock, (struct sockaddr *) &address, addrlen,
			       sock->file->f_flags);
	sockfd_put(sock);
	return error;
}

long grm_sys_execve (struct graphene_info *gi,
		     const char __user *filename,
		     const char __user *const __user *argv,
		     const char __user *const __user *envp)
{
	struct filename *tmp;
	int len;

	tmp = __getname();
	if (unlikely(!tmp))
		return -ENOMEM;

	tmp->name = __getname();
	if (unlikely(!tmp->name))
		return -ENOMEM;

	len = strncpy_from_user((char *) tmp->name, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		__putname(tmp->name);
		__putname(tmp);
		return len;
	}

	/* Reference monitor: check "filename" */
	if (gi) {
	}

	return KSYM(do_execve)(tmp, argv, envp);
}

static long grm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	char data[256];
	struct graphene_info *gi = (void *) file->private_data;
	long rv = 0;

	if (cmd != GRM_SYS_UNLINK &&
	    cmd != GRM_SYS_RMDIR) {
		if (copy_from_user(data, (void __user *) arg, _IOC_SIZE(cmd)))
			return -EFAULT;
	}

	switch (cmd) {

	case GRM_SYS_OPEN: {
		struct sys_open_param *param = (void *) &data;
		rv = grm_sys_open(gi, param->filename,
				  param->flags,
				  param->mode);
		break;
	}

	case GRM_SYS_STAT: {
		struct sys_stat_param *param = (void *) &data;
		rv = grm_sys_stat(gi, param->filename,
				  param->statbuf);
		break;
	}

	case GRM_SYS_UNLINK: {
		rv = grm_sys_unlink(gi, (const char __user *) arg);
		break;
	}

	case GRM_SYS_RMDIR: {
		rv = grm_sys_rmdir(gi, (const char __user *) arg);
		break;
	}

	case GRM_SYS_BIND: {
		struct sys_bind_connect_param *param = (void *) &data;
		rv = grm_sys_bind(gi, param->sockfd,
				  param->addr,
				  param->addrlen);
		break;
	}

	case GRM_SYS_CONNECT: {
		struct sys_bind_connect_param *param = (void *) &data;
		rv = grm_sys_connect(gi, param->sockfd,
				     param->addr,
				     param->addrlen);
		break;
	}

	case GRM_SYS_EXECVE: {
		struct sys_execve_param *param = (void *) &data;
		rv = grm_sys_execve(gi, param->filename,
				    param->argv,
				    param->envp);
		break;
	}

	case GRM_SET_SANDBOX: {
		break;
	}

	default:
		printk(KERN_ALERT "Graphene unknown ioctl %u %lu\n", cmd, arg);
		rv = -ENOSYS;
		break;
	}

	return rv;
}

static int grm_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int grm_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static struct file_operations grm_fops = {
	.owner		= THIS_MODULE,
	.release	= grm_release,
	.open		= grm_open,
	.unlocked_ioctl	= grm_ioctl,
	.compat_ioctl	= grm_ioctl,
	.llseek		= noop_llseek,
};

static struct miscdevice grm_dev = {
	.minor		= GRM_MINOR,
	.name		= "grm",
	.fops		= &grm_fops,
	.mode		= 0666,
};


static int __init grm_init(void)
{
	int rv;

	LOOKUP_KSYM(do_execve);

	rv = misc_register(&grm_dev);
	if (rv) {
		printk(KERN_ERR "Graphene error: "
		       "failed to add a char device (rv=%d)\n", rv);
		return rv;
	}

	printk(KERN_ALERT "Graphene Reference Monitor: Hello, world\n");
	return 0;
}

static void __exit grm_exit(void)
{
	misc_deregister(&grm_dev);
	printk(KERN_ALERT "Graphene Reference Monitor: Goodbye, cruel world\n");
}

module_init(grm_init);
module_exit(grm_exit);
