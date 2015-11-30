#include <errno.h>
#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <kernel-features.h>
#include <sysdep.h>
#include <shim_unistd.h>

#ifdef __NR_msgpersist
int msgpersist (int msqid, int cmd)
{
	return INLINE_SYSCALL (msgpersist, 2, msqid, cmd);
}
#endif
