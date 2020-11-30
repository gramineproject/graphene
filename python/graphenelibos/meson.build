conf = configuration_data()
conf.set('VERSION', meson.project_version())

init_py = configure_file(
    input: '__init__.py',
    output: '__init__.py',
    configuration: conf,
)

offsets_py = configure_file(
    input: '../../Pal/src/host/Linux-SGX/generated_offsets.py',
    output: '_offsets.py',
    copy: true,
)

install_data([
    init_py,
    offsets_py,
    '_aesm_pb2.py',
    'sgx_get_token.py',
    'sgx_sign.py',
], install_dir: join_paths(python3mod.sysconfig_path('platlib'), 'graphenelibos'))
