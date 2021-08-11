project('mbedtls', 'c')

# as our mbedtls will conflict with system's one, we need rpath at least for pf tools
mbedtls_install_dir = join_paths(get_option('libdir'), 'graphene', 'mbedtls')

# TODO this is custom_target, because we need to patch mbedtls before compiling
# PR for patch support in wraps: https://github.com/mesonbuild/meson/pull/4570
mbedtls_libs = custom_target('mbedtls',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@OUTPUT@',
        '--',
        'SHARED=1',
    ],

    input: ['Makefile', 'graphene.patch'],

    # NOTE we need real sonames here (.so.N, not .so), please keep synced with
    # mbedtls/library/Makefile, variables SOEXT_{TLS,X509,CRYPTO}
    output: [
        'libmbedcrypto.so.6',
        'libmbedcrypto.so',
        'libmbedtls.so.13',
        'libmbedtls.so',
        'libmbedx509.so.1',
        'libmbedx509.so',
    ],

    install: true,
    install_dir: mbedtls_install_dir,
)

mbedtls_pal_libs = custom_target('mbedtls_pal',
    command: [
        find_program('compile-pal.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        '@OUTPUT@',
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
#mbedtls_incpath = meson.current_source_dir() / 'include'

mbedtls_dep = declare_dependency(
    link_with: [mbedtls_libs[1], mbedtls_libs[3], mbedtls_libs[5]],
    include_directories: mbedtls_inc,
)
mbedtls_pal_dep = declare_dependency(
    link_with: mbedtls_pal_libs,
    include_directories: mbedtls_inc,
    compile_args: '-DMBEDTLS_CONFIG_FILE="mbedtls/config-pal.h"',
)
