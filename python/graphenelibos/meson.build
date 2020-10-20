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

python3.install_sources([
    init_py,
    'sgx_sign.py',
    offsets_py,
], subdir: 'graphenelibos')
