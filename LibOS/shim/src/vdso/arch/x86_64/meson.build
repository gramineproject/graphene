libos_vdso_so_dbg = shared_library('vdso',
    'vdso.c',
    name_prefix: '',
    name_suffix: 'so.dbg',
    include_directories: includes_libos,
    c_args: cflags_libos,
    link_args: [
        '-nostdlib',
        '-Wl,-T@0@'.format(join_paths(meson.current_source_dir(), 'vdso.lds')),
        '-Wl,-shared',
        '-Wl,--hash-style=both',
        '-Wl,--build-id',
        '-Wl,-Bsymbolic',
        '-Wl,-melf_x86_64',
        '-Wl,--no-undefined',
        '-Wl,-zmax-page-size=4096',
        '-Wl,-zcommon-page-size=4096',
        '-Wl,--soname=linux-vdso.so.1',
    ],
    link_depends: ['vdso.lds'],
)

# vdso.so is required to have no relocations. This rule checks it.
# Use default linker script to retain relocations if exist.
libos_vdso_for_reloc_check = shared_library(
    'vdso-for-reloc-check',
    name_prefix: '',
    name_suffix: 'so.dbg',
    objects: libos_vdso_so_dbg.extract_objects('vdso.c'),
    link_args: [
        '-nostdlib',
    ],
)

test(
    'libos-vdso-check-no-reloc',
    check_no_reloc_prog,
    args: [libos_vdso_for_reloc_check],
    suite: 'compiletime',
)

vdso_so = custom_target(
    'vdso.so',
    command: [objcopy, '-S', '@INPUT@', '@OUTPUT@'],
    input: libos_vdso_so_dbg,
    output: 'vdso.so',
)
