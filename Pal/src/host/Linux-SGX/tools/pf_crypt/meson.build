executable('graphene-sgx-pf-crypt',
    'pf_crypt.c',

    dependencies: [
        sgx_util_dep,
        mbedtls_dep,
        protected_files_dep,
    ],

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
