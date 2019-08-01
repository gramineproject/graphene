/* Dummy ELF entry point. Allows deterministic failure if accidentally
 * invoked by Graphene. No need to edit this file. */
.section .text
.global __entry
.p2align 4,0xcc
.type __entry,@function
__entry:
    int3
