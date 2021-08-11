executable('graphene-sgx-ias-request',
    'ias_request.c',

    dependencies: [
        sgx_util_dep,
        mbedtls_dep,
    ],

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
