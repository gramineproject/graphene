pal_linux_common_sources = [
    'bogomips.c',
    'debug_map.c',
    'file_utils.c',
    'graphene_unix_socket_addr.c',
    'main_exec_path.c',
    'timespec_utils.c',
    'topo_info.c',
]

pal_linux_common_sources_arch = [
    'syscall.S',
]
foreach src : pal_linux_common_sources_arch
    pal_linux_common_sources += join_paths('arch', host_machine.cpu_family(), src)
endforeach

pal_linux_common_sources = files(pal_linux_common_sources)
