Introduction to SGX
===================

Graphene project uses :term:`SGX` to securely run the software. SGX is a |nbsp|
complicated topic, which may be hard to learn, because the documentation is
scattered thorough official, reference documentation, blogposts and academic
papers. This page is an attempt to curate a |nbsp| dossier of available reading
material.

.. todo:: note about two SGX versions (SGX1 and SGX2)

Introduction-level
------------------

- `Overview of Intel SGX - Part 1, SGX Internals (Quarkslab)
  <https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html>`_
- `Overview of Intel SGX - Part 2, SGX Externals (Quarkslab)
  <https://blog.quarkslab.com/overview-of-intel-sgx-part-2-sgx-externals.html>`_
- `Wikipedia page <https://en.wikipedia.org/wiki/Software_Guard_Extensions>`_
- `Landing page <https://software.intel.com/en-us/sgx>`_
  (mostly marketing-quality)

About cryptography involed
--------------------------

- `Intel SGX Explained <https://eprint.iacr.org/2016/086>`_.

Official Documentation
----------------------

- `Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3D:
  System Programming Guide, Part 4
  <https://software.intel.com/en-us/download/intel-64-and-ia-32-architectures-sdm-volume-3d-system-programming-guide-part-4>`_
- `SDK for Linux <https://01.org/intel-software-guard-extensions/downloads>`_
  (download of both the binaries and the documentation)

Linux modules
-------------

At the time of this writing (December 2019) there are two modules in
circulation: one is distributed together with SDK (`github repo
<https://github.com/intel/linux-sgx-driver>`_) and another is being upstreamed
(`github repo <https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux>`_,
`LKML thread (v24) <https://lore.kernel.org/lkml/20191129231326.18076-1-jarkko.sakkinen@linux.intel.com/>`_).

Those two are not to be confused. The driver from SDK is currently unversally
used, because it is the only driver mentioned in downloads, but is likely
a |nbsp| dead end, because it won't be ever upstreamed. The driver being
upstreamed supports only SGX2 and requires :term:`DCAP`.

Installation instruction
------------------------

.. todo:: TBD

SGX terminology
---------------

.. as usual, keep this sorted

.. glossary::

   AEP
      .. todo:: TBD

   Attestation
      .. todo:: TBD

      .. seealso::

         :term:`Local Attestation`
            Description of Local Attestation

         :term:`Remote Attestation`
            Description of Remote Attestation

   DCAP
      Data Center Attestation Primitives

      .. todo:: TBD

   Enclave
      .. todo:: TBD

   EPC
      Enclave Page Cache

      .. todo:: TBD

   EPCM
      Enclave Page Cache Map

      .. todo:: TBD

   LE
      Launch Enclave

      .. todo:: TBD

   Local Attestation
      .. todo:: TBD

   MEE
      Memory Encryption Engine

      .. todo:: TBD

   PEBS
      Precise Event Based Sampling

      .. todo:: TBD

   PSW
      Platform Software

      .. todo:: TBD

   Remote Attestation
      .. todo:: TBD

   SECS
      SGX Enclave Control Structure

      .. todo:: TBD

   SSA
      Save State Area

      .. todo:: TBD

   SVN
      Security Version Number

      .. todo:: TBD

   TCS
      Thread Control Structure

      .. todo:: TBD
