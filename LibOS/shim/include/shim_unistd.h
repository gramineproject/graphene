#ifndef _SHIM_UNISTD_H_
#define _SHIM_UNISTD_H_

#ifdef IN_SHIM
#include "shim_types.h"
#else
/* XXX(borysp): This is hacky. Normally we would want to just include <sys/types.h> but it would
 * break some tests in "inline" directory. The main reason is that other header files are not
 * prepared for being included both in LibOS and in standalone binaries. Fortunately this header
 * only missed one type definition, hence this typedef suffices. */
typedef int pid_t;
#include <unistd.h>
#endif

#endif /* _SHIM_UNISTD_H_ */
