.. program:: is_sgx_available

======================================================================
:program:`is_sgx_available` -- Check environment for SGX compatibility
======================================================================

Synopsis
========

:command:`is_sgx_available` [--quiet]

Description
===========

`is_sgx_available` checks the CPU and operating system for :term:`SGX`
compatibility. A detailed report is printed unless suppressed by the
:option:`--quiet` option.

Command line arguments
======================

.. option:: --quiet

   Suppress displaying detailed report. See exit status for the result.

Exit status
===========

0
   SGX version 1 is available and ready

1
   No CPU cupport

2
   No BIOS support

3
   SGX Platform Software (:term:`PSW`) is not installed

4
   The ``aesmd`` :term:`PSW` daemon is not installed
