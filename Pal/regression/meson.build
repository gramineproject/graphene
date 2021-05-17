subdir('crt_init')

install_dir = join_paths(pkglibdir, 'tests/pal')

preload1 = shared_library('Preload1',
    'Preload1.c',
    'utils.c',

    c_args: [
        '-DIN_SHIM',

        # TODO
        '-Wno-discarded-qualifiers',
        '-Wno-unused-parameter',
    ],

    include_directories: include_directories(
        # for pal_host-arch.h
        join_paths('../include/arch', host_machine.cpu_family(), 'Linux-SGX'),
    ),

    dependencies: [
        common_dep,
        crt_init_shared_dep,
        libpal_dep,
    ],

    install: true,
    install_dir: install_dir,
)

preload2 = shared_library('Preload2',
    'Preload2.c',
    'utils.c',

    c_args: [
        '-DIN_SHIM',

        # TODO
        '-Wno-discarded-qualifiers',
        '-Wno-unused-parameter',
    ],

    include_directories: include_directories(
        # for pal_host-arch.h
        join_paths('../include/arch', host_machine.cpu_family(), 'Linux-SGX'),
    ),

    dependencies: [
        common_dep,
        crt_init_shared_dep,
        libpal_dep,
    ],

    install: true,
    install_dir: install_dir,
)

executables = [
    '..Bootstrap',
    'AttestationReport',
    'avl_tree_test',
    'Bootstrap',
    'Bootstrap3',
    'Bootstrap7',
    'Directory',
    'Event',
    'Exit',
    'File',
    'File2',
    'HelloWorld',
    'Hex',
    'Memory',
    'Misc',
    'Pie',
    'Pipe',
    'Process',
    'Process3',
    'Process4',
    'Select',
    'SendHandle',
    'Socket',
    'Symbols',
    'Tcp',
    'Thread2',
    'Udp',
    'normalize_path',
]

if host_machine.cpu_family() == 'x86_64'
    executables += [
        'Exception',
        'Exception2',
        'Segment',
        'Thread',
    ]
endif

foreach exe : executables
    executable(exe,
        '@0@.c'.format(exe),
        'utils.c',

        pie: exe == 'Pie',
        c_args: [
            '-DIN_SHIM',
            '-fno-stack-protector',
            '-fno-builtin',
            '-nostdlib',

            # TODO
            '-Wno-discarded-qualifiers',
            '-Wno-unused-parameter',
        ],

        include_directories: include_directories(
            # for AttestationReport
            '../src/host/Linux-SGX',

            # for pal_host-arch.h
            join_paths('../include/arch', host_machine.cpu_family(), 'Linux-SGX'),
        ),

        link_with: [
            preload1,
            preload2,
        ],

        dependencies: [
            common_dep,
            libpal_dep,
        ],

        install: true,
        install_dir: install_dir,
    )
endforeach
