project('mbedtls', 'c')

pkgconfig = import('pkgconfig')

mbedtls_libs_output = [
    'libmbedcrypto_graphene.so.6',
    'libmbedcrypto_graphene.so',
    'libmbedtls_graphene.so.13',
    'libmbedtls_graphene.so',
    'libmbedx509_graphene.so.1',
    'libmbedx509_graphene.so',
]

# TODO: This is custom_target, because we need to patch mbedtls before compiling.
# PR for patch support in wraps: https://github.com/mesonbuild/meson/pull/4570
mbedtls_libs = custom_target('mbedtls',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@OUTPUT@',
        '--',
        'SUFFIX=_graphene',
        'SHARED=1',
    ],

    input: ['Makefile', 'graphene.patch'],

    # NOTE we need real sonames here (.so.N, not .so), please keep synced with
    # mbedtls/library/Makefile, variables SOEXT_{TLS,X509,CRYPTO}
    output: mbedtls_libs_output,

    install: true,
    install_dir: get_option('libdir'),
)

pkgconfig.generate(
    name: 'mbedtls_graphene',
    filebase: 'mbedtls_graphene',
    description: 'A version of mbedtls patched for Graphene',
    libraries: [
        '-L${libdir}',
        '-Wl,-rpath,${libdir}',
        '-lmbedcrypto_graphene',
        '-lmbedtls_graphene',
        '-lmbedx509_graphene',
    ],
)

foreach output : mbedtls_libs_output
    meson.add_install_script('/bin/sh', '-c',
        ('ln -sf ../../../@0@ ' +
        '"$MESON_INSTALL_DESTDIR_PREFIX"/@1@/graphene/runtime/glibc/').format(
            output, get_option('libdir')))
endforeach

mbedtls_pal_libs = custom_target('mbedtls_pal',
    command: [
        find_program('compile-pal.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@OUTPUT@',
        '--',
        'SUFFIX=_pal',
    ],

    input: ['Makefile', 'graphene.patch'],

    output: [
        'libmbedcrypto_pal.a',
        'libmbedtls_pal.a',
        'libmbedx509_pal.a',
    ],

    build_by_default: true,
)

mbedtls_inc = include_directories('include')

mbedtls_dep = declare_dependency(
    link_with: [mbedtls_libs[1], mbedtls_libs[3], mbedtls_libs[5]],
    include_directories: mbedtls_inc,
)
mbedtls_pal_dep = declare_dependency(
    link_with: mbedtls_pal_libs,
    include_directories: mbedtls_inc,
    compile_args: '-DMBEDTLS_CONFIG_FILE="mbedtls/config-pal.h"',
)
