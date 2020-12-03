conf = configuration_data()
conf.set_quoted('IN_GIT', '')

if direct
    install_data('../Pal/src/host/Linux/libpal.so',
        install_dir: join_paths(pkglibdir, 'direct'))
    install_subdir('../Pal/src/host/Linux/gdb_integration',
        install_dir: join_paths(pkglibdir, 'direct'),
        exclude_directories: ['common'])
    install_subdir('../Pal/gdb_integration',
        install_dir: join_paths(pkglibdir, 'direct/gdb_integration/common'),
        strip_directory: true)

    hostpalpath_direct = join_paths(prefix, pkglibdir, 'direct')
    conf_graphene_direct = configuration_data()
    conf_graphene_direct.merge_from(conf)
    conf_graphene_direct.set('SGX', 0)
    conf_graphene_direct.set_quoted('HOST_PAL_PATH', hostpalpath_direct)
    conf_graphene_direct.set_quoted('LIBPAL_PATH', join_paths(hostpalpath_direct, 'libpal.so'))
    conf_graphene_direct.set_quoted('PAL_CMD', join_paths(hostpalpath_direct, 'libpal.so'))

    configure_file(
        input: 'pal_loader',
        output: 'graphene-direct',
        configuration: conf_graphene_direct,
        install_dir: get_option('bindir'),
    )
endif

if sgx
    install_data(
        '../Pal/src/host/Linux-SGX/pal-sgx',
        install_dir: join_paths(pkglibdir, 'sgx'))
    install_data(
        '../Pal/src/host/Linux-SGX/libpal.so',
        install_dir: join_paths(pkglibdir, 'sgx'))
    install_subdir('../Pal/src/host/Linux-SGX/gdb_integration',
        install_dir: join_paths(pkglibdir, 'sgx'),
        exclude_directories: ['common'])
    install_subdir('../Pal/gdb_integration',
        install_dir: join_paths(pkglibdir, 'sgx/gdb_integration/common'),
        strip_directory: true)

    hostpalpath_linux_sgx = join_paths(prefix, pkglibdir, 'sgx')
    conf_graphene_sgx = configuration_data()
    conf_graphene_sgx.merge_from(conf)
    conf_graphene_sgx.set('SGX', 1)
    conf_graphene_sgx.set_quoted('HOST_PAL_PATH', hostpalpath_linux_sgx)
    conf_graphene_sgx.set_quoted('LIBPAL_PATH', join_paths(hostpalpath_linux_sgx, 'libpal.so'))
    conf_graphene_sgx.set_quoted('PAL_CMD', join_paths(prefix, pkglibdir, 'sgx', 'pal-sgx'))

    configure_file(
        input: 'pal_loader',
        output: 'graphene-sgx',
        configuration: conf_graphene_sgx,
        install_dir: get_option('bindir'),
    )
endif
