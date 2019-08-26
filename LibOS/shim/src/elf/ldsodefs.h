#ifndef __LDSODEFS_H__
#define __LDSODEFS_H__

#include "elf.h"

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)       _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t)   _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ELFW(type) _ElfW(ELF, __ELF_NATIVE_CLASS, type)

/* We don't like the link_map form ld.so. This macro will be redefined */
#define D_PTR(sym) (sym)->d_un.d_ptr

/* ELF uses the PF_x macros to specify the segment permissions, mmap
   uses PROT_xxx.  In most cases the three macros have the values 1, 2,
   and 3 but not in a matching order.  The following macros allows
   converting from the PF_x values to PROT_xxx values.  */
#define PF_TO_PROT                                                                        \
    ((PROT_READ << (PF_R * 4)) | (PROT_WRITE << (PF_W * 4)) | (PROT_EXEC << (PF_X * 4)) | \
     ((PROT_READ | PROT_WRITE) << ((PF_R | PF_W) * 4)) |                                  \
     ((PROT_READ | PROT_EXEC) << ((PF_R | PF_X) * 4)) |                                   \
     ((PROT_WRITE | PROT_EXEC) << (PF_W | PF_X) * 4) |                                    \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) << ((PF_R | PF_W | PF_X) * 4)))

#endif /* ldsodefs.h */
