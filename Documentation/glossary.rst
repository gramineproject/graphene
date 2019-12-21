Glossary
========

.. keep this file sorted lexicographically

.. glossary::

   PAL
      Platform Adaptation Layer

      PAL is the layer of Graphene that implements a narrow Drawbridge-like ABI
      interface (with function names starting with the `Dk` prefix)

      .. seealso::

         https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/asplos2011-drawbridge.pdf

      Whenever Graphene requires a service from the host platform (memory
      allocation, thread management and synchronization, file system and network
      stacks, etc.), it calls the corresponding PAL functionality. The PAL ABI
      is host-platform agnostic and is backed by the host-platform specific PAL,
      for example, the Linux-SGX PAL.

   SGX
      Software Guard Extensions is a set of instructions on Intel processors for
      creating Trusted Execution Environments (:term:`TEE`). See
      :doc:`/sgx-intro`.

   Thread Control Block

      .. todo:: TBD
