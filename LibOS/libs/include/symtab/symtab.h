#pragma once

#include <stdint.h>

#include <elf/elf.h>
#include <sysdeps/generic/ldsodefs.h>

struct syminfo {
    const char* name;
    const void* addr;
    size_t len;
};

bool symtab_lookup_symbol(const char* name, struct syminfo* sinfo /* out */);

extern void *text_section;
