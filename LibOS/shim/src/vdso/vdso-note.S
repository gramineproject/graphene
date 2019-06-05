/* Copyright (C) 2018 Intel Corporation
                      Isaku Yamahata <isaku.yamahata at gmail.com>
                                     <isaku.yamahata at intel.com>
   All Rights Reserved.

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#if 0
/* notes section: .note.Linux which tells vDSO version */
__asm__(".pushsection .note.Linux, \"a\", @note\n");
struct __Elf64_Nhdr {
    Elf64_Nhdr nhdr;
    /* 6 = length of "Linux" (including tailing '\0')*/
    unsigned char name[6] __attribute__((aligned(sizeof(Elf64_Word))));
    /* unsigned char desc[0] __attribute__((aligned(sizeof(Elf64_Word)))); */
    unsigned int desc __attribute__((aligned(sizeof(Elf64_Word))));
};

const struct __Elf64_Nhdr __vdso_note_Linux
__attribute__((aligned(sizeof(Elf64_Word)), unused, section(".note.Linux"))) = {
    .nhdr.n_namesz = 6,
    .nhdr.n_descsz = sizeof(int),
    .nhdr.n_type = 0,
    .name = "Linux",
    .desc = 267008,  /* LINUX_VERSION_CODE */
};
const struct __Elf64_Nhdr __vdso_note_Linux_salt
__attribute__((aligned(sizeof(Elf64_Word)), unused, section(".note.Linux"))) = {
    .nhdr.n_namesz = 6,
    .nhdr.n_descsz = sizeof(int),
    .nhdr.n_type = 0x100,
    .name = "Linux",
    .desc = 0,  /* CONFIG_BUILD_SALT TODO */
};
__asm__(".popsection\n");
#endif

	/*
	 * there is no good way to tell gcc to use @note.
	 * gcc starts @progbits for C variables.
	 */
    .section .note.Linux, "a", @note

    .globl  __vdso_note_Linux
    .align 4
    .type   __vdso_note_Linux, @object
    .size   __vdso_note_Linux, 24
__vdso_note_Linux:
    .long   6
    .long   4
    .long   0
    .string "Linux"
    .zero   2
    .long   267008
    .globl  __vdso_note_Linux_salt
    .align 4
    .type   __vdso_note_Linux_salt, @object
    .size   __vdso_note_Linux_salt, 24
__vdso_note_Linux_salt:
    .long   6
	.long   4
	.long   256
	.string "Linux"
	.zero   2
	.long   0
