:orphan:

Introduction to SGX
===================

Graphene project uses :term:`SGX` to securely run software. SGX is
a |~| complicated topic, which may be hard to learn, because the documentation
is scattered through official/reference documentation, blogposts and academic
papers. This page is an attempt to curate a |~| dossier of available reading
material.

SGX is an umbrella name of *technology* that comprises several parts:

- CPU/platform *hardware features*: the new instruction set, new
  microarchitecture with the :term:`PRM` (:term:`EPC`) memory region and some
  new MSRs and some new logic in the MMU and so on;
- the SGX :term:`Remote Attestation` *infrastructure*, online services provided
  by Intel and/or third parties (see :term:`DCAP`);
- :term:`SDK` and assorted *software*.

SGX is still being developed. The current (March 2020) version of CPU features
is referred to as "SGX1" or simply "SGX" and is more or less finalized. All
new/changed instructions from original SGX are informally referred to as
":term:`SGX2`".

Features which might be considered part of SGX2:

- :term:`EDMM` (Enclave Dynamic Memory Management) is part of SGX2
- :term:`FLC` (Flexible Launch Control), not strictly part of SGX2, but was not
  part of original SGX hardware either

As of now there is hardware support (on a |~| limited set of CPUs) for FLC and
(on an even more limited set of CPUs) SGX2/EDMM. Most of the literature
available (especially introduction-level) concerns original SGX1 only.

Introductory reading
--------------------

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

- `Hardware compatibility list (unofficial) <https://github.com/ayeks/SGX-hardware>`__

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

Linux kernel drivers
^^^^^^^^^^^^^^^^^^^^

For historical reasons, there are three SGX drivers currently (March 2020):

- https://github.com/intel/linux-sgx-driver -- old one, does not support DCAP,
  deprecated

- https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver
  -- new one, out-of-tree, supports both non-DCAP software infrastructure (with
  old EPID remote-attestation technique) and the new DCAP (with new ECDSA and
  more "normal" PKI infrastructure).

- Upstreaming in-kernel SGX driver (see LKML patches) -- will be upstreamed one
  day, supports both non-DCAP and DCAP. The DCAP driver closely matches this
  upstreaming version.

  The in-tree driver will not be a |~| module
  (https://lore.kernel.org/linux-sgx/20190401225717.GA13450@linux.intel.com/),
  so "installation instructions" will likely be minimal.

  Also it will not require :term:`IAS` and kernel maintainers consider
  non-writable :term:`FLC` MSRs as non-functional SGX:
  https://lore.kernel.org/lkml/20191223094614.GB16710@zn.tnic/

SGX terminology
---------------

.. keep this sorted by full (not abbreviated) terms, leaving out generic terms
   like "Intel" and "SGX"

.. glossary::

   Architectural Enclaves
   AE

      A |~| set of "system" enclaves concerned with starting and attesting other
      enclaves.

      .. seealso::

         :term:`Provisioning Enclave`
         :term:`Launch Enclave`
         :term:`Quoting Enclave`

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

   Data Center Attestation Primitives
   DCAP

      A |~| software infrastructure provided by Intel as a reference
      implementation for the new ECDSA/:term:`PCS`-based remote attestation.
      Relies on the :term:`Flexible Launch Control` hardware feature. In
      principle this is a |~| special version of :term:`SDK`/:term:`PSW` that
      has a |~| reference launch enclave and is backed by the DCAP-enabled SGX
      driver.

      This allows for launching enclaves without Intel's remote infrastructure.
      But this requires deployment of own infrastructure, so is operationally
      more complicated. Therefore it is intended for server environments (where
      you control all the machines).

      .. seealso::

         Orientation Guide
            https://download.01.org/intel-sgx/dcap-1.0.1/docs/Intel_SGX_DCAP_ECDSA_Orientation.pdf

         :term:`EPID`
            A |~| way to launch enclaves with Intel's infrastructure, intended
            for client machines.

   Enclave
      .. todo:: TBD

   Enclave Dynamic Memory Management
   EDMM
      A |~| hardware feature of :term:`SGX2`, allows dynamic memory allocation,
      which in turn allows dynamic thread creation.

   Enclave Page Cache
   EPC

      .. todo:: TBD

   Enclave Page Cache Map
   EPCM

      .. todo:: TBD

   Enhanced Privacy Identification
   Enhanced Privacy Identifier
   EPID

      .. todo:: short description

      Contrary to DCAP, EPID may be understood as "opinionated", with most
      moving parts fixed and tied to services provided by Intel. This is
      intended for client enclaves and deprecated for server environments.

      .. seealso::

         :term:`DCAP`
            A way to launch enclaves without relying on the Intel's
            infrastructure.

   Flexible Launch Control
   FLC

      Hardware (CPU) feature that allows substituting :term:`Launch Enclave` for
      one not signed by Intel. A |~| change in SGX's EINIT logic to not require
      the EINITTOKEN from the Intel-based Launch Enclave. An |~| MSR, which can
      be locked at boot time, keeps the hash of the public key of the
      "launching" entity.

      With FLC, :term:`Launch Enclave` can be written by other companies (other
      than Intel) and must be signed with the key corresponding to the one
      locked in the MSR (a |~| reference Launch Enclave simply allows all
      enclaves to run). The MSR can also stay unlocked and then it can be
      modified at run-time by the VMM or the OS kernel.

      .. seealso::

         https://software.intel.com/en-us/blogs/2018/12/09/an-update-on-3rd-party-attestation
            Announcement

         :term:`DCAP`

   Launch Enclave
   LE

      .. todo:: TBD

      .. seealso::

         :term:`Architectural Enclaves`

   Local Attestation
      .. todo:: TBD

   Intel Attestation Service
   IAS

      Internet service provided by Intel for "old" :term:`EPID`-based remote
      attestation. Enclaves send SGX quotes to the client/verifier who will
      forward them to IAS to check their validity.

      .. seealso::

         :term:`PCS`
            Provisioning Certification Service, another Internet service
            provided by Intel.

   Memory Encryption Engine
   MEE

      .. todo:: TBD

   OCALL

      .. todo:: TBD

   SGX Platform Software
   PSW

      Software infrastructure provided by Intel with all special
      :term:`Architectural Enclaves` (:term:`Provisioning Enclave`,
      :term:`Quoting Enclave`, :term:`Launch Enclave`). This mainly refers to
      the "old" EPID/IAS-based remote attestation.

   Processor Reserved Memory
   PRM

      .. todo:: TBD

   Provisioning Enclave

      .. todo:: TBD

      .. seealso::

         :term:`Architectural Enclaves`

   Intel Provisioning Certification Service
   PCS

      New internet service provided by Intel for new ECDSA-based remote
      attestation. Enclave provider creates its own internal Attestation Service
      where it caches PKI collateral from Intel's PCS, and the verifier gets the
      certificate chain from the enclave provider to check validity.

      .. seealso::

         :term:`IAS`
            Intel Attestation Service, another Internet service.

   Quoting Enclave

      .. todo:: TBD

      .. seealso::

         :term:`Architectural Enclaves`

   Remote Attestation
      .. todo:: TBD

   Intel SGX Software Development Kit
   Intel SGX SDK
   SGX SDK
   SDK

      In the context of :term:`SGX`, this means a |~| specific piece of software
      supplied by Intel which helps people write enclaves packed into ``.so``
      files to be accessible like normal libraries (at least on Linux).
      Available together with a |~| kernel module and documentation.

   SGX Enclave Control Structure
   SECS

      .. todo:: TBD

   SGX2

      This refers to all new SGX instructions and other hardware features that
      were introduced after the release of the original SGX1.

      Encompasses at least :term:`EDMM`, but is still work in progress.

   State Save Area
   SSA

      .. todo:: TBD

   Security Version Number
   SVN

      .. todo:: TBD

   Trusted Execution Environment
   TEE

      .. todo:: TBD

   Trusted Computing Base
   TCB

      In context of :term:`SGX` this has the usual meaning: the set of all
      components that are critical to security. Any vulnerability in TCB
      compromises security. Any problem outside TCB is not a |~| vulnerability,
      i.e. |~| should not compromise security.

      In context of Graphene there is also a |~| different meaning
      (:term:`Thread Control Block`). Those two should not be confused.

   Thread Control Structure
   TCS

      .. todo:: TBD
