project(
    'graphene', 'c',
    version: '1.0',
    license: 'LGPLv3+',
)

prefix = get_option('prefix')
pkglibexecdir = get_option('libexecdir') / meson.project_name()
pkgdatadir = get_option('datadir') / meson.project_name()

python3 = import('python').find_installation('python3', modules: [
    'google.protobuf',
])

subdir('Runtime')
subdir('python')
