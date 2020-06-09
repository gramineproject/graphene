/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _DB_RTLD_H_
#define _DB_RTLD_H_

#include "pal_linux_defs.h"
#include "sysdeps/generic/ldsodefs.h"

#if USE_VDSO_GETTIME == 1
void setup_vdso_map(ElfW(Addr) addr);
#endif /* USE_VDSO_GETTIME */

#endif /* _DB_RTLD_H_ */
