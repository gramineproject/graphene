sgx_inc = [
    includes_pal_common,
    include_directories(
        '.',
        '../../../include/arch/@0@/Linux'.format(host_machine.cpu_family()),
        '../../../include/host/Linux-common',
        'protected-files',
    ),
]

subdir('protected-files')
subdir('tools')
