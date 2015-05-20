OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(pal_start);

SECTIONS
{
  /* Read-only sections, merged into text segment; */
  __text_start = .;
  . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
  .hash          : { *(.hash) }
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  .dynsym        : { *(.dynsym) }
  .dynstr        : { *(.dynstr) }
  .gnu.version   : { *(.gnu.version) }
  .gnu.version_d : { *(.gnu.version_d) }
  .gnu.version_r : { *(.gnu.version_r) }
  .rela.dyn      : { *(.rela.dyn) }
  .rela.plt      : { *(.rela.plt) }
  .init          : { *(.init) }
  .plt           : { *(.plt) *(.iplt) }
  .text :
  {
    /* the rest of text segments */
    *(.text .stub .text.*);
  }
  .fini          : { *(.fini) }
  .rodata :
  {
    /* the rest of rodata */
    *(.rodata .rodata.*)
  }
  .eh_frame_hdr  : { *(.eh_frame_hdr) }
  .eh_frame      : ONLY_IF_RO { KEEP(*(.eh_frame)) }
  __text_end = .;

  /* now adjust the address for the data segment */
  . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
  __data_start = .;
  .data.rel.ro   : { KEEP(*(.data.rel.ro)) }
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
  }
  .bss            :
  {
    *(.bss .bss.*)
    *(COMMON)
  }
  . = DATA_SEGMENT_END(.);
  __data_end = .;
}

