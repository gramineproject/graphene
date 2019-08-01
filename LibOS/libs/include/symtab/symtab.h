#ifndef __SYMTAB_H__
#define __SYMTAB_H__

#include <stdint.h>

#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

struct syminfo {
    const char* name;
    const void* addr;
    size_t len;
};

bool symtab_lookup_symbol(const char* name, struct syminfo* out_sinfo);
void symtab_unmap(void);

extern void *text_section;
#endif
