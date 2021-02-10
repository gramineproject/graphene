#ifndef SHIM_ENTRY_OFFSETS_H_
#define SHIM_ENTRY_OFFSETS_H_

/*
 * Offsets for patched code calling into Graphene. This file is included both in Graphene and in
 * patched code, and should contain only the constant definitions.
 */

#ifdef __ASSEMBLER__

SHIM_SYSCALLDB_OFFSET                    = 32
SHIM_REGISTER_LIBRARY_OFFSET             = 40

#else

#define SHIM_SYSCALLDB_OFFSET              32
#define SHIM_REGISTER_LIBRARY_OFFSET       40

#define SHIM_SYSCALLDB_OFFSET_STR         "32"
#define SHIM_REGISTER_LIBRARY_OFFSET_STR  "40"
#endif

#endif /* SHIM_ENTRY_OFFSETS_H_ */
