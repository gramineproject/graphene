.. program:: graphene-manifest
.. _graphene-manifest:

==============================================================
:program:`graphene-manifest` -- Graphene manifest preprocessor
==============================================================

Synopsis
========

:command:`graphene-manifest` [*OPTION*]... [*SOURCE-FILE* [*OUTPUT-FILE*]]

Description
===========

:program:`graphene-manifest` is used to preprocess manifests for Graphene using
`Jinja markup <https://jinja.palletsprojects.com/>`__.

Command line arguments
======================

.. option:: --define <key>=<value>, -D <key>=<value>

   Have a |~| variable available in the template.

Functions and constants available in templates
==============================================

.. default-domain:: py

.. data:: graphene.libos

   Path to :file:`libsysdb.so`.

.. function:: graphene.runtimedir([libc])

   The path to runtime directory with patched libc. The default libc is
   ``'glibc'``.

.. data:: python.stdlib

   ``stdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.platstdlib

   ``platstdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.purelib

   ``purelib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python.distlib

   On Debian systems, this is :file:`/usr/lib/python3/dist-packages`.

.. function:: python.get_path(...)

   `sysconfig.get_path
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_path>`__

.. function:: python.get_paths(...)

   `sysconfig.get_paths
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_paths>`__

.. data:: python.implementation

   `sys.implementation
   <https://docs.python.org/3/library/sys.html#sys.implementation>`__

.. data:: env.[ENVVAR]

   The content of ``$ENVVAR`` environment variable.

.. function:: ldd(\*executables)

   List of libraries which are linked from *executables*. Each library is
   provided at most once.

Example
=======

:file:`manifest.template`:

.. code-block:: jinja

   loader.preload = "file:{{ graphene.libos }}"
   libos.entrypoint = "{{ entrypoint }}"
   loader.env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}:/usr{{ arch_libdir }}"

   [fs.mount.runtime]
   type = "chroot"
   path = "/lib"
   uri = "file:{{ graphene.runtimedir() }}"

   [sgx.trusted_files]
   entrypoint = "file:{{ entrypoint }}"
   runtime = "file:{{ graphene.runtimedir() }}/"

:file:`Makefile`:

.. code-block:: make

   %.manifest: manifest.template
      graphene-manifest \
         -Dentrypoint=$(ENTRYPOINT) \
         -Darch_libdir=$(ARCH_LIBDIR) \
         $< $@
