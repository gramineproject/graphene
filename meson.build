project(
    'graphene', 'c',
    version: '1.0',
    license: 'LGPLv3+',
)

prefix = get_option('prefix')
pkglibexecdir = join_paths(get_option('libexecdir'), meson.project_name())
pkgdatadir = join_paths(get_option('datadir'), meson.project_name())

# TODO: after deprecating 18.04/bionic, update this to import('python')
python3mod = import('python3')
python3 = python3mod.find_python('python3', modules: [
    'google.protobuf',
])

subdir('Runtime')
subdir('python')
