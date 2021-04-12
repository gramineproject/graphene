Packaging and distributing
==========================

Graphene project aims to support two most recent releases of the long-lived
distributions (eg. Debian, Ubuntu LTS, [the CentOS replacement that will
hopefuly emerge soon], ...).

Currently supported distributions:

- Ubuntu (20.04 LTS, 18.04 LTS).

Exceptions
----------

Linux kernel
^^^^^^^^^^^^
Because upstream support for SGX was only merged relatively recently and in
non-longterm release, together with the fact that EPID attestation is
unsupported in upstream driver, **it is acceptable to require the user to use
kernel other that provided by distro**.

glibc
^^^^^
Glibc is a special case, because we need to provide the version supported by the
distribution **or a later version**, which is inverse from the usual dependency
relation that we need to support the version from distro or earlier. Therefore

varia
^^^^^
Maintainer tools, examples, etc. need not run on all distros.

Packaging guide
---------------

TBD

Acknowledgements
----------------

Distro support policy was inspired by `Libvirt's policy
<https://libvirt.org/platforms.html>`__.
