#ifndef _KSYM_H
#define _KSYM_H

#include <linux/kallsyms.h>

#define KSYM(name) __ksym_##name
#define IMPORT_KSYM(name) __typeof(name) * KSYM(name)
#define IMPORT_KSYM_PROTO(name, ret, ...) ret (*KSYM(name)) (__VA_ARGS__)
#define LOOKUP_KSYM(name)						\
	({								\
		KSYM(name) = (void *) kallsyms_lookup_name(#name);	\
		if (!KSYM(name))					\
			pr_err("Unknown symbol: " #name "\n");		\
		KSYM(name) ? 0 : -EINVAL;				\
	})

#endif
