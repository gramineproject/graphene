conf = configuration_data()
conf.set('VERSION', meson.project_version())

init_py = configure_file(
    input: '__init__.py',
    output: '__init__.py',
    configuration: conf,
)

python3_pkgdir = join_paths(python3mod.sysconfig_path('platlib'), 'graphenelibos')

install_data([
    init_py,
], install_dir: python3_pkgdir)

if sgx
    offsets_py = configure_file(
        input: '../../Pal/src/host/Linux-SGX/generated_offsets.py',
        output: '_offsets.py',
        configuration: configuration_data(),
    )

    install_data([
        offsets_py,
        '_aesm_pb2.py',
        'sgx_get_token.py',
        'sgx_sign.py',
    ], install_dir: python3_pkgdir)
endif
