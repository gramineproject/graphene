LTP FOR GRAPHENE
================

Just run ``make regression``, or ``make SGX=1 regression``.

Test results are reported as an XML file, ``ltp.xml`` or ``ltp-sgx.xml``, which
is for consumption in Jenkins. There is also rudimentary logging.

To run a single testcase, execute the following commands::

    cd <LTP_REPO>/install/testcases/bin/
    <GRAPHENE_DIR>/Runtime/pal_loader [SGX] <TEST_BINARY>

In this way, one can debug one particular syscall testcase.

``ltp.cfg``
------------

This is a file in ``.ini`` format
(https://docs.python.org/library/configparser). Lines starting with ``#`` and
``;`` are comments. Section names are names of the binaries. There is one
special section, ``[DEFAULT]``, which holds defaults for all binaries and some
global options.

Global options:
- ``sgx``: if true-ish, run under SGX (default: false)
- ``jobs``: run that many tests in parallel (default is 1 under SGX and number of
  CPUs otherwise); **WARNING:** Because EPC has limited size, test suite may
  become unstable if more than one test is running concurrently under SGX
- ``junit-classname``: classname to be shown in JUnit-XML report (``LTP``)
- ``loader``: path to ``pal_loader`` (default: ``./pal_loader``)
- ``ltproot``: path to LTP (default: ``./install``)

Per-binary options:
- ``skip``: if true-ish, do not attempt to run the binary (default: false).
- ``timeout`` in seconds (default: ``30``)
- ``must-pass``: if not specified (the default), treat the whole binary as
  a single test and report its return code; if specified, only those subtests
  (numbers separated by whitespace) are expected to pass, but they must be in
  the report, so if the binary TBROK'e earlier and did not run the test, report
  failure; empty ``must-pass`` is valid (means nothing is required); **NOTE**
  that this depends on stability of subtest numbering, which may be affected by
  various factors, among those the glibc version and/or what is ``#define``\ d
  in the headers (see ``signal03`` for example).

Another config file path can be specified using ``--config`` argument to
``./runltp_xml.py``. Options can be overridden as parameters to ``-o`` argument.
See ``--help``.

A lot of LTP tests cause problems in Graphene. The ones we've already analyzed
should have an appropriate comment in the ``ltp.cfg`` file.
