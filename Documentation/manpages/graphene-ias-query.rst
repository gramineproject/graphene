.. program:: graphene-ias-query

=========================================================================
:program:`graphene-ias-query` -- Submit Intel Attestation Service request
=========================================================================

Synopsis
========

:command:`graphene-ias-query` [*OPTIONS*] *FILE*

Description
===========

:program:`graphene-ias-query` is a |~| quick-and-dirty program which queries IAS
v4 API (currently only development endpoint) and formats the response. No
signature checking is performed.

The quote is to be provided as hex-encoded *FILE* (``-`` means standard input).

Command line arguments
======================

.. option:: --key KEY

   API key.

.. option:: -h, --help

   Display usage.

Python API
==========

The functionality is available as Python API:

.. code-block:: python

   from graphenelibos import ias

   api = ias.API(key=...)
   report = api.get_report(quote=bytes.fromhex(open('quote.txt').read()))
   print(report.quote_status)
   assert report.quote_status == api.QuoteStatus.OK
