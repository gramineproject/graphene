#
# Project configuration, options, modules, scripts
#

project(
    'graphene', 'c',
    version: '1.0',
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
    ],
)

prefix = get_option('prefix')
pkglibdir = join_paths(get_option('libdir'), meson.project_name())
pkgdatadir = join_paths(get_option('datadir'), meson.project_name())

direct = get_option('direct') == 'enabled'
sgx = get_option('sgx') == 'enabled'

if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    add_project_arguments('-DDEBUG', language: 'c')
endif

cc = meson.get_compiler('c')
objcopy = find_program('objcopy')

# TODO: after deprecating 18.04/bionic, update this to import('python')
python3mod = import('python3')
python3 = python3mod.find_python()

subdir('Scripts')

#
# Common checks and flags
#

# not all compilers support mstack-protector-guard, so use stack protector only if supported
cflags_stack_protector = [
    '-fstack-protector-strong',
    '-mstack-protector-guard=tls',
    '-mstack-protector-guard-reg=%gs',
    '-mstack-protector-guard-offset=8',
]
if not cc.has_multi_arguments(cflags_stack_protector)
    cflags_stack_protector = '-fno-stack-protector'
endif

#
# The compilation
#

subdir('LibOS')
subdir('Runtime')
subdir('python')
