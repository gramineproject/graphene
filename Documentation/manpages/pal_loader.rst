.. program:: pal_loader

======================================
:program:`pal_loader` -- Run something
======================================

.. note::

   This page is a stub.

Synopsis
========

:command:`pal_loader` [SGX] [GDB] {<*MANIFEST*> | <*EXECUTABLE*>} [<*ARGS*> ...]

Description
===========

Command line arguments
======================

.. option:: SGX

   Enable :term:`SGX`.

   .. seealso::

      :envvar:`SGX environment variable <SGX>`
         For an equivalent.

Environment variables
=====================

.. envvar:: SGX

   If not empty and not ``0``, enable :term:`SGX`. Could be used instead of
   :option:`SGX option <SGX>`.
