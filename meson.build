#
# Project configuration, options, modules, scripts
#

project(
    'graphene',
    'c', 'cpp',
    version: '1.2-rc1',
    license: 'LGPLv3+',

    # DISTRO            EOL         meson_version
    # xenial            2021.04     0.29
    # xenial-backports  2021.04     0.40
    # bionic            2023.04     0.45
    # buster            2022        0.49
    # buster-backports  2022        0.52
    # focal             2025.04     0.53
    #
    # https://wiki.ubuntu.com/Releases
    # https://wiki.debian.org/DebianReleases#Production_Releases
    meson_version: '>=0.45',

    default_options: [
        'c_std=c11',
        'cpp_std=c++14',
        'werror=true',
    ],
)

subdir('Scripts')

prefix = get_option('prefix')
pkglibdir = join_paths(get_option('libdir'), meson.project_name())
pkgdatadir = join_paths(get_option('datadir'), meson.project_name())

direct = get_option('direct') == 'enabled'
sgx = get_option('sgx') == 'enabled'
skeleton = get_option('skeleton') == 'enabled'

dcap = get_option('dcap') == 'enabled'

cc = meson.get_compiler('c')
objcopy = find_program('objcopy')

# TODO: after deprecating 18.04/bionic, update this to import('python')
python3mod = import('python3')
python3 = python3mod.find_python()

add_project_arguments(
    '-Wa,--noexecstack',

    '-Wall',
    '-Wextra',

    '-Wmissing-prototypes',
    '-Wstrict-prototypes',
    '-Wwrite-strings',

    '-Wno-sign-compare', #TODO

    cc.get_supported_arguments(
        '-Wtrampolines',
        '-Wnull-dereference',
    ),

    language: 'c')

if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    add_project_arguments('-DDEBUG', language: 'c')
endif

#
# Common checks and flags
#

# Not all compilers support mstack-protector-guard, so use stack protector only if supported.
# Graphene-custom stack protector uses the canary stored in the TCB (same for both in LibOS and PAL)
# at offset 0x8.
if host_machine.cpu_family() == 'x86_64'
    cflags_custom_stack_protector = [
        '-fstack-protector-strong',
        '-mstack-protector-guard=tls',
        '-mstack-protector-guard-reg=%gs',
        '-mstack-protector-guard-offset=8',
    ]
else
    cflags_custom_stack_protector = [
        '-fstack-protector-strong',
    ]
endif

if not cc.has_multi_arguments(cflags_custom_stack_protector)
    cflags_custom_stack_protector = '-fno-stack-protector'
endif

#
# Dependencies
#

if sgx
    threads_dep = dependency('threads')

    # this one is bizarre, will be compiled in different ways: one for LibOS, one for PAL
    mbedtls_proj = subproject('mbedtls-mbedtls-2.26.0')
    mbedtls_dep = mbedtls_proj.get_variable('mbedtls_dep')
    mbedtls_install_dir = mbedtls_proj.get_variable('mbedtls_install_dir') # for install_rpath
#   mbedtls_pal_dep = mbedtls_proj.get_variable('mbedtls_pal_dep')

    libcurl_dep = dependency('libcurl', version: '>=7.58.0')

    cjson_dep = dependency('cjson', required: false)
    if not cjson_dep.found()
        # on Debian < 11 .pc is not installed and dependency() fails, so we fallback to
        # cc.find_library()
        cjson_dep = cc.find_library('cjson', required: false)
    endif
    if not cjson_dep.found()
        # Ubuntu 18.04 does not have cjson at all
        cjson_dep = subproject('cJSON-1.7.12').get_variable('cjson_dep')
    endif

    if dcap
        sgx_dcap_quoteverify_dep = cc.find_library('sgx_dcap_quoteverify')
    endif
endif

#
# The compilation
#

subdir('common')
subdir('Pal')
subdir('LibOS')
subdir('Runtime')
subdir('python')

run_target('clang-format', command: [meson_clang_format_prog])
