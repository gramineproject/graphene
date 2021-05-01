project(
    'graphene', 'c',
    version: '1.0',
    license: 'LGPLv3+',

    # Don't uncomment until we either update to module('python') and/or
    # meson>=0.54, because meson<0.54.2 has a bug which displays bogus warnings
    # about deprecated versions: https://github.com/mesonbuild/meson/issues/7080
#   meson_version: '>=0.45',
)

prefix = get_option('prefix')
pkglibdir = join_paths(get_option('libdir'), meson.project_name())
pkgdatadir = join_paths(get_option('datadir'), meson.project_name())

direct = get_option('direct') == 'enabled'
sgx = get_option('sgx') == 'enabled'

# TODO: after deprecating 18.04/bionic, update this to import('python')
python3mod = import('python3')
python3 = python3mod.find_python()

subdir('LibOS')
subdir('Runtime')
subdir('python')
