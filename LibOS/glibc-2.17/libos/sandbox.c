#include <errno.h>
#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <kernel-features.h>
#include <sysdep.h>
#include <shim_unistd.h>

#ifdef __NR_sandbox_create
long sandbox_create(int flags, const char *fs_sb, struct net_sb *net_sb)
{
	return INLINE_SYSCALL (sandbox_create, 3, flags, fs_sb, net_sb);
}
#endif

#ifdef __NR_sandbox_attach
int sandbox_attach(unsigned int sbid)
{
	return INLINE_SYSCALL (sandbox_attach, 1, sbid);
}
#endif

#ifdef __NR_sandbox_current
long sandbox_current(void)
{
	return INLINE_SYSCALL (sandbox_current, 0);
}
#endif
