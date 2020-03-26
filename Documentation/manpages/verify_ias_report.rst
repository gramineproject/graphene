.. program:: verify_ias_report

========================================================================
:program:`verify_ias_report` -- Submit Intel Attestation Service request
========================================================================

Synopsis
========

:command:`verify_ias_report` [*OPTION*]...

Description
===========

`verify_ias_report` verifies attestation report retrieved from the Intel
Attestation Service (using ``ias_request`` for example). It also verifies
that the quote contained in the IAS report contains expected values.

Command line arguments
======================

.. option:: -h, --help

   Display usage.

.. option:: -v, --verbose

   Print more information.

.. option:: -m, --msb

   Print/parse hex strings in big-endian order.

.. option:: -r, --report-path

   IAS report to verify.

.. option:: -s, --sig-path

   Path to the IAS report's signature.

.. option:: -o, --allow-outdated-tcb

   Treat IAS status GROUP_OUT_OF_DATE as OK.

.. option:: -n, --nonce

   Nonce that's expected in the report (optional).

.. option:: -S, --mr-signer

   Expected mr_signer field (hex string, optional).

.. option:: -E, --mr-enclave

   Expected mr_enclave field (hex string, optional).

.. option:: -R, --report-data

   Expected report_data field (hex string, optional).

.. option:: -P, --isv-prod-id

   Expected isv_prod_id field (hex string, optional).

.. option:: -V, --isv-svn

   Expected isv_svn field (hex string, optional).

.. option:: -i, --ias-pubkey

   Path to IAS public RSA key (PEM format, optional).
