'''Python support for Graphene'''

__version__ = '@VERSION@'

_CONFIG_PKGLIBDIR = '@PKGLIBDIR@'
_CONFIG_LIBDIR = '@LIBDIR@'

if __version__.startswith('@'):
    raise RuntimeError(
        'You are attempting to run the tools from repo, without installing. '
        'Please install graphene before running Python tools. See '
        'https://graphene.readthedocs.io/en/latest/building.html.')
