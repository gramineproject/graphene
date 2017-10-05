#ifndef _GRAPHENE_RM_H
#define _GRAPHENE_RM_H

#include <linux/ioctl.h>

#define GRM_FILE	"/dev/grm"
#define GRM_MINOR	241

struct sys_open_param {
	const char	*filename;
	int		flags;
	__kernel_mode_t	mode;
};

struct sys_stat_param {
	const char	*filename;
	struct kstat	*statbuf;
};

struct sys_unlink_param {
	const char	*filename;
};

struct sys_bind_connect_param {
	int		sockfd;
	struct sockaddr	*addr;
	int		addrlen;
};

struct sys_execve_param {
	const char	*filename;
	const char * const *argv;
	const char * const *envp;
};

/* Ioctl codes */
#define GRM_SYS_OPEN    _IOR('k', 0, struct sys_open_param)
#define GRM_SYS_STAT    _IOR('k', 1, struct sys_stat_param)
#define GRM_SYS_UNLINK  _IOR('k', 2, struct sys_unlink_param)
#define GRM_SYS_BIND    _IOR('k', 3, struct sys_bind_connect_param)
#define GRM_SYS_CONNECT _IOR('k', 4, struct sys_bind_connect_param)
#define GRM_SYS_EXECVE  _IOR('k', 5, struct sys_execve_param)


#endif // _GRAPHENE_IPC_H
