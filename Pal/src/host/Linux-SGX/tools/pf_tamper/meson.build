executable('graphene-sgx-pf-tamper',
    'pf_tamper.c',

    dependencies: [
        sgx_util_dep,
        mbedtls_dep,
        protected_files_dep,
    ],

    include_directories: common_inc, # for api.h

    install: true,
    install_rpath: join_paths(get_option('prefix'), get_option('libdir')),
)
