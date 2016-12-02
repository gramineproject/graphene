#ifndef _KSYM_H
#define _KSYM_H

#include <linux/kallsyms.h>

#define __KSYM(name) __ksym_##name
#define KSYM(name) ({ BUG_ON(!__KSYM(name)); __KSYM(name); })
#define IMPORT_KSYM(name) __typeof(name) * __KSYM(name)
#define IMPORT_KSYM_PROTO(name, ret, ...) ret (*__KSYM(name)) (__VA_ARGS__)
#define LOOKUP_KSYM(name)						\
	do {								\
		__KSYM(name) = (void *) kallsyms_lookup_name(#name);	\
		if (!__KSYM(name)) {					\
			pr_err("Unknown symbol: " #name "\n");		\
			return -EINVAL;					\
		}							\
	} while (0)

#endif
