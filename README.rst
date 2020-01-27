******************************************
Graphene Library OS with Intel SGX Support
******************************************

.. image:: https://readthedocs.org/projects/graphene/badge/?version=latest
   :target: http://graphene.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

*A Linux-compatible Library OS for Multi-Process Applications*

.. This is not |~|, because that is in rst_prolog in conf.py, which GitHub cannot parse.
   GitHub doesn't appear to use it correctly anyway...
.. |nbsp| unicode:: 0xa0
   :trim:

.. highlight:: sh


What is Graphene?
=================

Graphene is a |nbsp| lightweight guest OS, designed to run a |nbsp| single
application with minimal host requirements. Graphene can run applications in an
isolated environment with benefits comparable to running a |nbsp| complete OS in
a |nbsp| virtual machine -- including guest customization, ease of porting to
different OSes, and process migration.

Graphene supports native, unmodified Linux applications on any platform.
Currently, Graphene runs on Linux and Intel SGX enclaves on Linux platforms.

With Intel SGX support, Graphene can secure a |nbsp| critical application in
a |nbsp| hardware-encrypted memory region. Graphene can protect applications
from a |nbsp| malicious system stack with minimal porting effort.

Our papers describe the motivation, design choices, and measured performance of
Graphene:

- `EuroSys 2014 <http://www.cs.unc.edu/~porter/pubs/tsai14graphene.pdf>`__
- `ATC 2017 <http://www.cs.unc.edu/~porter/pubs/graphene-sgx.pdf>`__

How to get Graphene?
====================

The latest version of Graphene can be cloned from GitHub::

   git clone https://github.com/oscarlab/graphene.git

At this time Graphene is available only as source code. `Building instructions
are available <https://graphene.readthedocs.io/en/latest/building.html>`__.

How to run an application in Graphene?
======================================

Graphene library OS uses the PAL (``libpal.so``) as a loader to bootstrap
applications in the library OS. To start Graphene, PAL (``libpal.so``) will have
to be run as an executable, with the name of the program, and a |nbsp| "manifest
file" (per-app configuration) given from the command line. Graphene provides
three options for specifying the programs and manifest files:

- option 1 (automatic manifest)::

   [PATH TO Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
   (Manifest file: "[PROGRAM].manifest" or "manifest")

- option 2 (given manifest)::

   [PATH TO Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

- option 3 (manifest as a script)::

   [PATH TO MANIFEST]/[MANIFEST] [ARGUMENTS]...
   (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Running an application requires some minimal configuration in the application's
manifest file. A |nbsp| sensible manifest file will include paths to the library
OS and other libraries the application requires; environment variables, such as
``LD_LIBRARY_PATH``; and file systems to be mounted.

Here is an example manifest file::

    loader.preload = file:LibOS/shim/src/libsysdb.so
    loader.env.LD_LIBRAY_PATH = /lib
    fs.mount.libc.type = chroot
    fs.mount.libc.path = /lib
    fs.mount.libc.uri = file:[relative path to Graphene root]/Runtime

More examples can be found in the test directories (``LibOS/shim/test``). We
have also tested several applications, such as GCC, Bash, and Apache.
The manifest files for these applications are provided in the
individual directories under ``LibOS/shim/test/apps``.

For the full documentation of the Graphene manifest syntax, see the `Graphene
documentation
<https://graphene.readthedocs.io/en/latest/manifest-syntax.html>`__.

Getting help
============

For the full documentation of the Graphene, see the `Graphene documentation
<https://graphene.readthedocs.io/en/latest/>`__.

For any questions, please send an email to <support@graphene-project.io>
(`public archive <https://groups.google.com/forum/#!forum/graphene-support>`__).

For bug reports, post an issue on our GitHub repository:
<https://github.com/oscarlab/graphene/issues>.


Deprecated Code
===============

We have some branches with legacy code (use at your own risk).

Docker support
--------------

We are actively working on adding a proper Docker support. You can find the old
and deprecated implementation on `DEPRECATED/gsc
<https://github.com/oscarlab/graphene/tree/DEPRECATED/gsc>`__ branch.

Build with Kernel-Level Sandboxing
----------------------------------

This feature is marked as EXPERIMENTAL and no longer exists in the master branch.
See `EXPERIMENTAL/linux-reference-monitor
<https://github.com/oscarlab/graphene/tree/EXPERIMENTAL/linux-reference-monitor>`__.
