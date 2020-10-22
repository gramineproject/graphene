===============
Protected Files
===============

Protected files (PF) are a new type of files that can be specified in the manifest (SGX only).
They are encrypted on disk and transparently decrypted when accessed by Graphene or by application
running inside Graphene.

Features
========

- Data is encrypted (confidentiality) and integrity protected (tamper resistance).
- File swap protection (a PF can only be accessed when in a specific path).
- Transparency (Graphene application sees PFs as regular files, no need to modify the application).

The following new manifest elements are added::

   sgx.protected_files_key = "<16-byte hex value>"
   sgx.protected_files.<name> = "file:<host path>"


Example
-------

::

   sgx.protected_files.pf_1 = "file:tmp/some_file"
   sgx.protected_files.pf_2 = "file:tmp/some_dir"
   sgx.protected_files.pf_3 = "file:tmp/another_dir/some_file"

Paths specifying PF entries can be files or directories. If a directory is specified,
all existing files/directories within are registered as protected recursively (and are expected
to be encrypted in the PF format). New files created in a protected directory are automatically
treated as protected.

Limitations
-----------

Metadata currently limits PF path size to 512 bytes and filename size to 260 bytes.

NOTE
----

``sgx.protected_files_key`` specifies the encryption key and is only a temporary implementation.
This key should be provisioned to the enclave with local/remote attestation in the future.

The ``tools`` directory contains the ``pf_crypt`` utility that converts files to/from the protected
format.

Internal protected file format in this version was ported from the `SGX SDK
<https://github.com/intel/linux-sgx/tree/1eaa4551d4b02677eec505684412dc288e6d6361/sdk/protected_fs>`_.

Tests
=====

Tests in ``LibOS/shim/test/fs`` now contain PF tests too (target is still ``test``).
Target to run just non-PF tests is ``fs-test``.

TODO
====

- Truncating protected files is not yet implemented.
- The recovery file feature is disabled, this needs to be discussed if it's needed in Graphene.
- Tests for invalid/malformed/corrupted files need to be ported to the new format.
