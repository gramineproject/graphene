#ifndef ASM_OFFSETS_BUILD_H
#define ASM_OFFSETS_BUILD_H

#define DEFINE(name, value)     \
    __asm__ volatile(".ascii \" #define " #name " %0 \"\n":: "i"(value))

#define OFFSET(name, str, member)   DEFINE(name, offsetof(struct str, member))
#define OFFSET_T(name, str_t, member) DEFINE(name, offsetof(str_t, member))

#endif /* ASM_OFFSETS_BUILD_H */
