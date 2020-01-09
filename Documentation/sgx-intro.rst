Introduction to SGX
===================

Graphene project uses :term:`SGX` to securely run the software. SGX is a |nbsp|
complicated topic, which may be hard to learn, because the documentation is
scattered thorough official, reference documentation, blogposts and academic
papers. This page is an attempt to curate a |nbsp| dossier of available reading
material.

SGX is still being developed. The current (December 2019) version is referred to
as SGX1 and the next version is called SGX2. The distinguishing feature of SGX2
is :term:`EDMM` (Enclave Dynamic Memory Management). Another feature, which is
not strictly part of SGX2, but AFAIU was not part of original SGX instruction
set is :term:`DCAP` (Data Center Attestation Primitives). As of now there is
hardware support available for DCAP but not SGX2 per se (EDMM).

.. todo:: some kind of introduction

Introduction-level
------------------

- Quarkslab's two-part "Overview of Intel SGX":

  - `Part 1, SGX Internals (Quarkslab)
    <https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html>`__
  - `Part 2, SGX Externals (Quarkslab)
    <https://blog.quarkslab.com/overview-of-intel-sgx-part-2-sgx-externals.html>`__

- `MIT's deep dive in SGX architecture <https://eprint.iacr.org/2016/086>`__.

- Intel's whitepapers:

  - `Innovative Technology for CPU Based Attestation and Sealing
    <https://software.intel.com/en-us/articles/innovative-technology-for-cpu-based-attestation-and-sealing>`__
  - `Innovative Instructions and Software Model for Isolated Execution
    <https://software.intel.com/en-us/articles/innovative-instructions-and-software-model-for-isolated-execution>`__
  - `Using Innovative Instructions to Create Trustworthy Software Solutions [PDF]
    <https://software.intel.com/sites/default/files/article/413938/hasp-2013-innovative-instructions-for-trusted-solutions.pdf>`__
  - `Slides from ISCA 2015 <https://sgxisca.weebly.com/>`__
    (`actual slides [PDF] <https://software.intel.com/sites/default/files/332680-002.pdf>`__)

Official Documentation
----------------------

- `Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3D:
  System Programming Guide, Part 4
  <https://software.intel.com/en-us/download/intel-64-and-ia-32-architectures-sdm-volume-3d-system-programming-guide-part-4>`__
- `SDK for Linux <https://01.org/intel-software-guard-extensions/downloads>`__
  (download of both the binaries and the documentation)

Academic Research
-----------------

- `Intel's collection of academic papers
  <https://software.intel.com/en-us/sgx/documentation/academic-research>`__,
  likely the most comprehensive list of references

Installation Instructions
-------------------------

.. todo:: TBD

Linux modules
^^^^^^^^^^^^^

At the time of this writing (December 2019) there are two modules in
circulation: one is distributed together with SDK (`github repo
<https://github.com/intel/linux-sgx-driver>`__) and another is being upstreamed
(`github repo <https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux>`__,
`LKML thread (v24) <https://lore.kernel.org/lkml/20191129231326.18076-1-jarkko.sakkinen@linux.intel.com/>`__).

Those two are not to be confused. The driver from SDK is currently universally
used, because it is the only driver mentioned in downloads, but it won't be ever
upstreamed, so it is likely that it's days are numbered.

The driver being upstreamed requires :term:`DCAP`. AFAIU the SDK driver supports
DCAP but does not require it.

SGX terminology
---------------

.. as usual, keep this sorted

.. glossary::

   AEP
      .. todo:: TBD

   AEX
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

      Also called Flexible Launch Control (FIXME is this accurate?). This allows
      for launching enclaves without Intel's remote infrastructure (FIXME only
      launch enclaves? does this also include local and remote attestation?).
      But this requires deployment of own infrastructure, so is operationally
      more complicated.

      .. todo:: TBD

      .. seealso::

         :term:`EPID`
            A |nbsp| way to launch enclaves with Intel's infrastructure.

   EDMM
      Enclave Dynamic Memory Management, a |nbsp| feature of SGX2.

   Enclave
      .. todo:: TBD

   EPC
      Enclave Page Cache

      .. todo:: TBD

   EPCM
      Enclave Page Cache Map

      .. todo:: TBD

   EPID
      Enhanded Privacy Identification

      May also be referred to as Intel Launch Control (FIXME is this accurate?).

      .. todo:: TBD

      .. seealso::

         :term:`DCAP`
            A way to launch enclaves without relying in Intel's infrastructure.

   LE
      Launch Enclave

      .. todo:: TBD

   Local Attestation
      .. todo:: TBD

   MEE
      Memory Encryption Engine

      .. todo:: TBD

   OCALL
      .. todo:: TBD

   PEBS
      Precise Event Based Sampling

      .. todo:: TBD

   PSW
      Platform Software

      .. todo:: TBD

   Remote Attestation
      .. todo:: TBD

   SDK
      Software Development Kit

      In the context of :term:`SGX`, this means a |nbsp| specific piece supplied
      by Intel which helps people write enclaves packed into ``.so`` files to be
      accessible like normal libraries (at least on Linux). Availabe together
      with a |nbsp| kernel module and documentation.

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
