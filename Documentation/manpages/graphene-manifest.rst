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

   Have a |~| variable available in template.

Functions and constants available in template
=============================================

.. default-domain:: py

.. data:: libos

   Path to :file:`libsysdb.so`.

.. function:: get_runtimedir([libc])

   The path to runtime directory with patched libc. The default libc is
   ``'glibc'``.

.. data:: python_stdlib

   ``stdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python_platstdlib

   ``platstdlib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python_purelib

   ``purelib`` installation path from `sysconfig module
   <https://docs.python.org/library/3/sysconfig.html#installation-paths>`__

.. data:: python_distlib

   On Debian systems, this is :file:`/usr/lib/python3/dist-packages`.

.. function:: python_get_path(...)

   `sysconfig.get_path
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_path>`__

.. function:: python_get_paths(...)

   `sysconfig.get_paths
   <https://docs.python.org/3/library/sysconfig.html#sysconfig.get_paths>`__

.. data:: python_implementation

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

   loader.preload = "file:{{ libos }}"
   libos.entrypoint ="file:{{ entrypoint }}"
   loader.env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}:/usr{{ arch_libdir }}"

   [fs.mount.runtime]
   type = "chroot"
   path = "/lib"
   uri = "file:{{ get_runtimedir() }}"

   [sgx.trusted_files]
   entrypoint = "file:{{ entrypoint }}"
   runtime = "file:{{ get_runtimedir() }}/"

:file:`Makefile`:

.. code-block:: make

   %.manifest: manifest.template
      graphene-manifest \
         -Dentrypoint=$(ENTRYPOINT) \
         -Darch_libdir=$(ARCH_LIBDIR) \
         $< $@
