OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
  /* Read-only sections, merged into text segment; */
  __load_address = .;
  . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  .dynsym        : { *(.dynsym) }
  .dynstr        : { *(.dynstr) }
  .gnu.version   : { *(.gnu.version) }
  .gnu.version_d : { *(.gnu.version_d) }
  .gnu.version_r : { *(.gnu.version_r) }
  .rela.dyn      : { *(.rela.*) }
  .init          : { KEEP(*(.init)) }
  .plt           : { *(.plt) *(.iplt) }
  .text :
  {
    /* the rest of text segments */
    __code_address = .;
    *(.text .stub .text.*);
    . = ALIGN(8);
    __migrate_name = .;
    SORT(*)(SORT(.migrate_name.*));
    __migrate_func = .;
    SORT(*)(SORT(.migrate.*));
    __resume_func = .;
    SORT(*)(SORT(.resume.*));
    __code_address_end = .;
  }
  .fini          : { KEEP(*(.fini)) }
  .rodata :
  {
    /* the rest of rodata */
    *(.rodata .rodata.*)
  }
  .eh_frame_hdr  : { *(.eh_frame_hdr) }
  .eh_frame      : ONLY_IF_RO { KEEP(*(.eh_frame)) }
  .hash          : { *(.hash) }

  /* now adjust the address for the data segment */
  . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
  .eh_frame      : ONLY_IF_RW { KEEP(*(.eh_frame)) }
  .ctors         : { KEEP(*(.ctors)) }
  .dtors         : { KEEP(*(.dtors)) }
  .jcr           : { KEEP(*(.jcr)) }
  .dynamic       : { *(.dynamic) }
  .got           : { *(.got) *(.igot) }
  .got.plt       : { *(.got.plt) *(.igot.plt) }
  .data :
  {
    /* the rest of data segment */
    *(.data .data.*);
    . = ALIGN(64);
    __profile = .;
    *(SORT(.profile));
    __profile_end = .;
    . = ALIGN(CONSTANT(COMMONPAGESIZE));
    __migratable = .;
    *(.migratable);
    __migratable_end = .;
    . = ALIGN(CONSTANT(COMMONPAGESIZE));
  }
  .bss            :
  {
    *(.bss .bss.*)
    *(COMMON)
  }
  __load_address_end = .;
  . = DATA_SEGMENT_END(.);
}

