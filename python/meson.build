subdir('graphenelibos')

install_data([
    'graphene-manifest',
], install_dir: get_option('bindir'))

if sgx
    install_data([
        'graphene-sgx-get-token',
        'graphene-sgx-sign',
    ], install_dir: get_option('bindir'))
endif
