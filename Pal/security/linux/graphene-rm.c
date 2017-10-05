#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <asm/mman.h>

#include "graphene-rm.h"
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

long grm_sys_open (const char __user *filename, int flags, mode_t mode)
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

long grm_sys_stat (const char __user *filename, struct kstat __user *statbuf)
{
	struct filename *tmp;
	char *kname;
	struct kstat stat;
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

	__putname(kname);

	error = vfs_stat(filename, &stat);
	if (error)
		return error;

	return copy_to_user(statbuf, &stat, sizeof(stat)) ? -EFAULT : 0;
}

long grm_sys_unlink (const char __user *filename)
{
	return -ENOSYS;
}

long grm_sys_bind (int sockfd, struct sockaddr __user *addr, int addrlen)
{
	return -ENOSYS;
}

long grm_sys_connect (int sockfd, struct sockaddr __user *addr, int addrlen)
{
	return -ENOSYS;
}

long grm_sys_execve (const char __user *filename,
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

	return KSYM(do_execve)(tmp, argv, envp);
}

static long grm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	char data[256];
	long rv = 0;

	if (copy_from_user(data, (void __user *) arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	switch (cmd) {

	case GRM_SYS_OPEN: {
		struct sys_open_param *param = (void *) &data;
		rv = grm_sys_open(param->filename,
				  param->flags,
				  param->mode);
		break;
	}

	case GRM_SYS_STAT: {
		struct sys_stat_param *param = (void *) &data;
		rv = grm_sys_stat(param->filename,
				  param->statbuf);
		break;
	}

	case GRM_SYS_UNLINK: {
		struct sys_unlink_param *param = (void *) &data;
		rv = grm_sys_unlink(param->filename);
		break;
	}

	case GRM_SYS_BIND: {
		struct sys_bind_connect_param *param = (void *) &data;
		rv = grm_sys_bind(param->sockfd,
				  param->addr,
				  param->addrlen);
		break;
	}

	case GRM_SYS_CONNECT: {
		struct sys_bind_connect_param *param = (void *) &data;
		rv = grm_sys_connect(param->sockfd,
				     param->addr,
				     param->addrlen);
		break;
	}

	case GRM_SYS_EXECVE: {
		struct sys_execve_param *param = (void *) &data;
		rv = grm_sys_execve(param->filename,
				    param->argv,
				    param->envp);
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
