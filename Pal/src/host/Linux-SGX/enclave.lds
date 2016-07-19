OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

PHDRS
{
  headers PT_PHDR PHDRS;
  text PT_LOAD FILEHDR PHDRS;
  data PT_LOAD;
  dynamic PT_DYNAMIC;
  tls PT_TLS;
  gnu_stack PT_GNU_STACK;
}

SECTIONS
{
  /* Read-only sections, merged into text segment; */
  pal_start_addr = .;
  __text_start = .;
  . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
  text_start = .;
  .note.gnu.build-id : { *(.note.gnu.build-id) } :text
  .gnu.hash      : { *(.gnu.hash) } :text
  .dynsym        : { *(.dynsym) } :text
  .dynstr        : { *(.dynstr) } :text
  .gnu.version   : { *(.gnu.version) } :text
  .gnu.version_d : { *(.gnu.version_d) } :text
  .rela.dyn      : { *(.rela.dyn) } :text
  .rela.plt      : { *(.rela.plt) } :text
  .init          : { *(.init) } :text
  .plt           : { *(.plt) *(.iplt) } :text
  .text :
  {
    section_text = .;
    /* the rest of text segments */
    *(.text .stub .text.*);
  } :text
  .fini          : { *(.fini) } :text
  .eh_frame_hdr  : { *(.eh_frame_hdr) } :text
  .eh_frame      : ONLY_IF_RO { KEEP(*(.eh_frame)) } :text
  .rodata :
  {
    section_rodata = .;
    /* the rest of rodata */
    *(.rodata .rodata.*)
  } :text
  __text_end = .;

  /* now adjust the address for the data segment */
  . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
 __data_start = .;
  .tdata         :
  {
    *(.tdata)
  } :tls

  .dynamic       :
  {
    section_dynamic = .;
    *(.dynamic)
  } :data :dynamic


  data_start = .;
  .data.rel.ro   : { KEEP(*(.data.rel.ro)) } :data
  .ctors         : { KEEP(*(.ctors)) } :data
  .dtors         : { KEEP(*(.dtors)) } :data
  .jcr           : { KEEP(*(.jcr)) } :data
  .got           : { *(.got) *(.igot) } :data
  .got.plt       : { *(.got.plt) *(.igot.plt) } :data
  .data          :
  {
    section_data = .;
    /* the rest of data segment */
    *(.data .data.*);
  } :data
  .bss           :
  {
    section_bss = .;
    *(.bss)
    *(COMMON)
  } :data
  __data_end = .;

  . = DATA_SEGMENT_END(.);
}

