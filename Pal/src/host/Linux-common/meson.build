pal_linux_common_sources_enclave = files(
    'bogomips.c',
    'graphene_unix_socket_addr.c',
)
pal_linux_common_sources_urts = files(
    'debug_map.c',
    'file_utils.c',
    'main_exec_path.c',
    'timespec_utils.c',
    'topo_info.c',
]

pal_linux_common_sources_urts_arch = [
    'syscall.S',
]
foreach src : pal_linux_common_sources_urts_arch
    pal_linux_common_sources_urts += files(join_paths('arch', host_machine.cpu_family(), src))
endforeach


pal_linux_common_sources = [
    pal_linux_common_sources_enclave,
    pal_linux_common_sources_urts,
]
