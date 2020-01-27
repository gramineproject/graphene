Remote attestation demo
=======================

.. warning::

   This is a misfeature. It does not provide any security guarantees. Expect
   this to be replaced by something that works.

.. highlight:: text

To enable tests for the built-in remote attestation feature for Graphene-SGX,
obtain a SPID and a subscription key (can be linkable or unlinkable) from the
Intel API Portal:
<https://api.portal.trustedservices.intel.com/EPID-attestation>.

Specify the SPID, subscription key, and the type of the SPID/key in the
manifest::

   sgx.ra_client_spid = <SPID>
   sgx.ra_client_key = <KEY>
   sgx.ra_client_linkable = 1 # or 0 if the SPID/key is unlinkable (default)

If the remote attestation feature is enabled, Graphene-SGX will terminate if the
platform is not successfully verified by the Intel Attestation Service (IAS).
The feature ensures that Graphene-SGX only executes on genuine, up-to-date SGX
hardware.

To enable remote attestation tests in ``Pal/regression``, specify the following
variables:

.. code-block:: sh

   cd PAL/regression
   make SGX=1 RA_CLIENT_SPID=<SPID> RA_CLIENT_KEY=<KEY>
   make SGX=1 sgx-tokens

If you receive a ``GROUP_OUT_OF_DATE`` status from IAS, this status indicates
that your CPU is out of date and can be vulnerable. If you wish to bypass this
error, you can specify the following option in the manifest::

   sgx.ra_accept_group_out_of_date = 1

Similarly, if you receive a ``CONFIGURATION_NEEDED`` status from IAS, this
status indicates that additional configuration of your SGX platform may be
needed. If you wish to bypass this error, you can specify the following option
in the manifest::

   sgx.ra_accept_configuration_needed = 1

*Security advisories:*

- ``GROUP_OUT_OF_DATE`` may indicate that the firmware (microcode) of you CPU is
  not updated according to INTEL-SA-00233 (Load/store data sampling) and
  INTEL-SA-00161 (L1 terminal fault). It is recommended that you keep the BIOS
  of your platform up-to-date.

- If you receive status ``CONFIGURATION_NEEDED`` from the IAS after updating
  your BIOS, you may need to disable hyperthreading in your BIOS to mitigate L1
  terminal fault.
