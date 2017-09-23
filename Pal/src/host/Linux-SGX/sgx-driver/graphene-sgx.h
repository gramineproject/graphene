#ifndef _X86_GSGX_USER_H
#define _X86_GSGX_USER_H

#include <linux/ioctl.h>
#include <linux/stddef.h>
#include <linux/types.h>

#include "isgx_version.h"

#define GSGX_FILE	"/dev/gsgx"
#define GSGX_MINOR	MISC_DYNAMIC_MINOR

#if SDK_DRIVER_VERSION >= KERNEL_VERSION(1, 8, 0)

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#if SDK_DRIVER_VERSION > KERNEL_VERSION(1, 8, 0)
#include "linux-sgx-driver/sgx_user.h"
#else // 1.8
#include "linux-sgx-driver/isgx_user.h"
#endif 

#else // SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0)

#include "linux-sgx-driver/isgx_user.h"

#define GSGX_IOCTL_ENCLAVE_CREATE	_IOWR('p', 0x01, struct gsgx_enclave_create)
#define GSGX_IOCTL_ENCLAVE_ADD_PAGES	_IOW('p',  0x02, struct gsgx_enclave_add_pages)
#define GSGX_IOCTL_ENCLAVE_INIT		_IOW('p',  0x03, struct gsgx_enclave_init)

#define GSGX_ENCLAVE_CREATE_NO_ADDR	((unsigned long) -1)

struct gsgx_enclave_create {
	uint64_t src;
};

#define GSGX_ENCLAVE_ADD_PAGES_SKIP_EEXTEND	0x1
#define GSGX_ENCLAVE_ADD_PAGES_REPEAT_SRC	0x2

struct gsgx_enclave_add_pages {
	uint64_t flags;
	uint64_t addr;
	uint64_t user_addr;
	uint64_t size;
	uint64_t secinfo;
};

struct gsgx_enclave_init {
	uint64_t addr;
	uint64_t sigstruct;
	uint64_t einittoken;
};

#endif /* SDK_DRIVER_VERSION < KERNEL_VERSION(1, 8, 0) */

#if SDK_DRIVER_VERSION == KERNEL_VERSION(1, 6, 0)
#define SGX_SUCCESS			ISGX_SUCCESS
#define SGX_INVALID_SIG_STRUCT		ISGX_INVALID_SIG_STRUCT
#define SGX_INVALID_ATTRIBUTE		ISGX_INVALID_ATTRIBUTE
#define SGX_BLKSTATE			ISGX_BLKSTATE
#define SGX_INVALID_MEASUREMENT		ISGX_INVALID_MEASUREMENT
#define SGX_NOTBLOCKABLE		ISGX_NOTBLOCKABLE
#define SGX_PG_INVLD			ISGX_PG_INVLD
#define SGX_LOCKFAIL			ISGX_LOCKFAIL
#define SGX_INVALID_SIGNATURE		ISGX_INVALID_SIGNATURE
#define SGX_MAC_COMPARE_FAIL		ISGX_MAC_COMPARE_FAIL
#define SGX_PAGE_NOT_BLOCKED		ISGX_PAGE_NOT_BLOCKED
#define SGX_NOT_TRACKED			ISGX_NOT_TRACKED
#define SGX_VA_SLOT_OCCUPIED		ISGX_VA_SLOT_OCCUPIED
#define SGX_CHILD_PRESENT		ISGX_CHILD_PRESENT
#define SGX_ENCLAVE_ACT			ISGX_ENCLAVE_ACT
#define SGX_ENTRYEPOCH_LOCKED		ISGX_ENTRYEPOCH_LOCKED
#define SGX_INVALID_LICENSE		ISGX_INVALID_LICENSE
#define SGX_PREV_TRK_INCMPL 		ISGX_PREV_TRK_INCMPL
#define SGX_PG_IS_SECS 			ISGX_PG_IS_SECS
#define SGX_INVALID_CPUSVN		ISGX_INVALID_CPUSVN
#define SGX_INVALID_ISVSVN		ISGX_INVALID_ISVSVN
#define SGX_UNMASKED_EVENT		ISGX_UNMASKED_EVENT
#define SGX_INVALID_KEYNAME		ISGX_INVALID_KEYNAME
#define SGX_POWER_LOST_ENCLAVE		ISGX_POWER_LOST_ENCLAVE
#define SGX_LE_ROLLBACK			ISGX_LE_ROLLBACK
#endif

#endif /* _X86_GSGX_USER_H */
