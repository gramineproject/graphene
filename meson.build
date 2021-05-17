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
        'werror=true',
    ],
)

subdir('Scripts')

prefix = get_option('prefix')
pkglibdir = join_paths(get_option('libdir'), meson.project_name())
pkgdatadir = join_paths(get_option('datadir'), meson.project_name())

direct = get_option('direct') == 'enabled'
sgx = get_option('sgx') == 'enabled'

cc = meson.get_compiler('c')
objcopy = find_program('objcopy')
protoc_c_prog = find_program('protoc-c')

# TODO: after deprecating 18.04/bionic, update this to import('python')
python3mod = import('python3')
python3 = python3mod.find_python()
python3_platlib = run_command(
    python3, get_python_platlib_prog, get_option('prefix')).stdout()
python3_pkgdir = join_paths(python3_platlib, 'graphenelibos')


add_project_arguments(
    '-Wa,--noexecstack',

    '-Wall',
    '-Wextra',

    '-Wmissing-prototypes',
    '-Wstrict-prototypes',
    '-Wwrite-strings',

    cc.get_supported_arguments(
        '-Wtrampolines',
        '-Wnull-dereference',

        # Some of the code uses alignof on expressions, which is a GNU extension.
        # Silence Clang - it complains but does support it.
        '-Wno-gnu-alignof-expression',
    ),

    language: 'c')

if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    add_project_arguments('-DDEBUG', language: 'c')
endif

if sgx
    conf_sgx = configuration_data()

    # SGX driver options (in make, this was ISGX_DRIVER_PATH and link-intel-driver.py)
    sgx_driver = get_option('sgx_driver')
    sgx_driver_include_path = get_option('sgx_driver_include_path')
    sgx_driver_device = get_option('sgx_driver_device')

    if sgx_driver == 'upstream'
        conf_sgx.set('CONFIG_SGX_DRIVER_UPSTREAM', true)
        if sgx_driver_include_path == ''
            sgx_driver_include_path = '/usr/src/linux-headers-@0@/arch/x86/include'.format(
                run_command('uname', '-r').stdout().strip())
        endif
        if sgx_driver_device == ''
            sgx_driver_device = '/dev/sgx_enclave'
        endif

    elif sgx_driver == 'oot'
        conf_sgx.set('CONFIG_SGX_DRIVER_OOT', true)
        if sgx_driver_include_path == ''
            sgx_driver_include_path = '/opt/intel/linux-sgx-driver'
        endif
        if sgx_driver_device == ''
            sgx_driver_device = '/dev/isgx'
        endif

    else # dcap1.6 or dcap1.10
        if sgx_driver == 'dcap1.6'
            conf_sgx.set('CONFIG_SGX_DRIVER_DCAP_1_6', true)
        elif sgx_driver == 'dcap1.10'
            conf_sgx.set('CONFIG_SGX_DRIVER_DCAP_1_10', true)
        endif

        if sgx_driver_device == ''
            sgx_driver_device = '/dev/sgx/enclave'
        endif
        if sgx_driver_include_path == ''
            sgx_driver_include_path = (
                '/opt/intel/SGXDataCenterAttestationPrimitives/driver/linux/include')
        endif
    endif

    conf_sgx.set_quoted('CONFIG_SGX_DRIVER_DEVICE', sgx_driver_device)
endif

#
# Common checks and flags
#

# Not all compilers support mstack-protector-guard, so use stack protector only if supported.
# Graphene-custom stack protector uses the canary stored in the TCB (same for both in LibOS and PAL)
# at offset 0x8.
cflags_custom_stack_protector = [
    '-fstack-protector-strong',
    '-mstack-protector-guard=tls',
    '-mstack-protector-guard-reg=%gs',
    '-mstack-protector-guard-offset=8',
]
if not cc.has_multi_arguments(cflags_custom_stack_protector)
    cflags_custom_stack_protector = '-fno-stack-protector'
endif

#
# The compilation
#

subdir('include')
subdir('proto')

subdir('common')
subdir('Pal')
subdir('LibOS')
subdir('Runtime')
subdir('python')

run_target('clang-format', command: [meson_clang_format_prog])
