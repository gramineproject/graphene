conf = configuration_data()
conf.set('VERSION', meson.project_version())

init_py = configure_file(
    input: '__init__.py',
    output: '__init__.py',
    configuration: conf,
)

python3.install_sources([
    init_py,
], subdir: 'grapheneos')
