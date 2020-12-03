conf = configuration_data()
conf.set_quoted('IN_GIT', '')

if direct
    install_data('../Pal/src/host/Linux/libpal.so',
        install_dir: join_paths(pkglibexecdir, 'direct'))
    install_subdir('../Pal/src/host/Linux/gdb_integration',
        install_dir: join_paths(pkglibexecdir, 'direct'),
        exclude_files: ['debug_map_gdb.py'])
    install_subdir('../Pal/gdb_integration',
        install_dir: join_paths(pkglibexecdir, 'direct'))
    meson.add_install_script('/bin/sh', '-c',
        'ln -s libpal.so "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
            join_paths(pkglibexecdir, 'direct', 'loader')))

    hostpalpath_direct = join_paths(prefix, pkglibexecdir, 'direct')
    conf_graphene_direct = configuration_data()
    conf_graphene_direct.merge_from(conf)
    conf_graphene_direct.set('SGX', 0)
    conf_graphene_direct.set_quoted('HOST_PAL_PATH', hostpalpath_direct)
    conf_graphene_direct.set_quoted('LIBPAL_PATH', join_paths(hostpalpath_direct, 'libpal.so'))
    conf_graphene_direct.set_quoted('PAL_CMD', join_paths(hostpalpath_direct, 'loader'))

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
        install_dir: join_paths(pkglibexecdir, 'sgx'))
    install_data(
        '../Pal/src/host/Linux-SGX/libpal.so',
        install_dir: join_paths(pkglibexecdir, 'sgx'))
    install_subdir('../Pal/src/host/Linux-SGX/gdb_integration',
        install_dir: join_paths(pkglibexecdir, 'sgx'),
        exclude_files: ['debug_map_gdb.py'])
    install_subdir('../Pal/gdb_integration',
        install_dir: join_paths(pkglibexecdir, 'sgx'))

    meson.add_install_script('/bin/sh', '-c',
        'ln -s pal-sgx "$MESON_INSTALL_DESTDIR_PREFIX"/@0@'.format(
            join_paths(pkglibexecdir, 'direct', 'loader')))

    hostpalpath_linux_sgx = join_paths(prefix, pkglibdir, 'sgx')
    conf_graphene_sgx = configuration_data()
    conf_graphene_sgx.merge_from(conf)
    conf_graphene_sgx.set('SGX', 1)
    conf_graphene_sgx.set_quoted('HOST_PAL_PATH', hostpalpath_linux_sgx)
    conf_graphene_sgx.set_quoted('LIBPAL_PATH', join_paths(hostpalpath_linux_sgx, 'libpal.so'))
    conf_graphene_sgx.set_quoted('PAL_CMD', join_paths(prefix, pkglibdir, 'sgx', 'loader'))

    configure_file(
        input: 'pal_loader',
        output: 'graphene-sgx',
        configuration: conf_graphene_sgx,
        install_dir: get_option('bindir'),
    )

    install_data(
        'crt1.o',
        'crti.o',
        'crtn.o',
        'ld-linux-x86-64.so.2',
        'libc.so',
        'libc.so.6',
        'libdl.so.2',
        'libm.so.6',
        'libnss_dns.so.2',
        'libpthread.so.0',
        'libresolv.so.2',
        'librt.so.1',
        'libsysdb.a',
        'libsysdb.so',
#       'libsysdb_debug.so',
        'libthread_db.so.1',
        'libutil.so.1',
        install_dir: join_paths(pkglibdir, 'sgx', 'runtime'))
endif
