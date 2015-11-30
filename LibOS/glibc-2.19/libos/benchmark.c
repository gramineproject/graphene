#include <errno.h>
#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <kernel-features.h>
#include <sysdep.h>
#include <shim_unistd.h>

#ifdef __NR_benchmark_rpc
int benchmark_rpc(pid_t pid, int times, const void * buf, size_t size)
{
	return INLINE_SYSCALL (benchmark_rpc, 4, pid, times, buf, size);
}
#endif

#ifdef __NR_send_rpc
size_t send_rpc (pid_t pid, const void * buf, size_t size)
{
	return INLINE_SYSCALL (send_rpc, 3, pid, buf, size);
}
#endif

#ifdef __NR_recv_rpc
size_t recv_rpc (pid_t * pid, void * buf, size_t size)
{
	return INLINE_SYSCALL (recv_rpc, 3, pid, buf, size);
}
#endif
