************************
Introduction to Graphene
************************

What is Graphene Library OS?
============================

Graphene is a |~| lightweight guest OS, designed to run a |~| single application
with minimal host requirements. Graphene can run applications in an isolated
environment with benefits comparable to running a |~| complete OS in a |~|
virtual machine -- including guest customization, ease of porting to different
OSes, and process migration.

Graphene supports running Linux applications using the :term:`Intel SGX <SGX>`
(Software Guard Extensions) technology (we call this version **Graphene-SGX**).
With Intel SGX, applications are secured in hardware-encrypted memory regions
(called SGX enclaves). SGX protects code and data in the enclave against
privileged software attacks and against physical attacks on the hardware off the
CPU package (e.g., cold-boot attacks on RAM). Graphene is able to run unmodified
applications inside SGX enclaves, without the toll of manually porting the
application to the SGX environment.

What Hosts Does Graphene Currently Run On?
==========================================

Graphene was developed to encapsulate all host-specific code in one layer,
called the Platform Adaptation Layer, or :term:`PAL`. Thus, if there is a PAL
for a |~| given host, the library OS and applications will "just work".

Porting Graphene to a |~| new host only requires :doc:`porting PAL
<pal/porting>`, by implementing the :doc:`pal/host-abi` using OS features of the
host. To date, we ported Graphene to FreeBSD (this port is not maintained
anymore) and Linux (the latter also with Intel SGX support). Support for more
hosts is expected in the future.

How to Build and Run Graphene?
==============================

See :doc:`quickstart` for instructions how to quickly build and run Graphene.
For full build instructions, see :doc:`building`.

How to Contact the Maintainers?
===============================

For bug reports, post an issue on our GitHub repository:
<https://github.com/oscarlab/graphene/issues>.

For any questions, please send an email to <support@graphene-project.io>
(`public archive <https://groups.google.com/forum/#!forum/graphene-support>`__).

How Do I Contribute to the Project?
===================================

Thank you for your interest! Please see :doc:`devel/contributing`.



*****************
Table of Contents
*****************

.. toctree::
   :caption: Introduction
   :maxdepth: 2

   quickstart
   building
   manifest-syntax
   supported-syscalls
   sample-apps
   glossary
   howto-doc

.. toctree::
   :caption: Manual pages
   :maxdepth: 1
   :glob:

   manpages/*

.. toctree::
   :caption: Developing Graphene
   :maxdepth: 1

   devel/contributing
   devel/coding-style
   devel/setup
   devel/debugging
   devel/new-syscall
   devel/sgx-process-creation
   devel/signal-handling

.. toctree::
   :caption: LibOS

   libos/shim-init

.. toctree::
   :caption: PAL

   pal/porting
   pal/host-abi

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
