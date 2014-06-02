#include <errno.h>
#include <sysdep-cancel.h>
#include <sys/syscall.h>
#include <kernel-features.h>
#include <sysdep.h>
#include <shim_unistd.h>

#ifdef __NR_checkpoint
int checkpoint (const char * filename)
{
	return INLINE_SYSCALL (checkpoint, 1, filename);
}
#endif
