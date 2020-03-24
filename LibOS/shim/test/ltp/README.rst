LTP FOR GRAPHENE
================

Just run ``make regression``, or ``make SGX=1 regression``.

Test results are reported as an XML file, ``ltp.xml`` or ``ltp-sgx.xml``, which
is for consumption in Jenkins. There is also rudimentary logging.

To run a single testcase, execute the following commands::

    cd <LTP_REPO>/opt/ltp/testcases/bin/
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
- ``ltproot``: path to LTP (default: ``./opt/ltp``)

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


Flaky tests
-----------

::

   clone02 - Invokes clone with CLONE_VM but without either of CLONE_THREAD or CLONE_VFORK, i.e., a
   process sharing its parents address space. Graphene doesn't support this exotic model. Bug exposed by #1034.

   waitpid03,1 and 2 - fails about 20% of the time
   preadv01 - fails intermittently in CI - perhaps an unrelated bug?
   preadv01,2
   preadv01,3
   preadv01,4

   waitpid02 - Gets a segfault in debug build fairly often
   waitpid02,1
   waitpid02,2
   waitpid02,3

   clock_nanosleep01,11 - Pretty prone to hanging, don't think it is a timeout

   sendfile05,1 - pretty prone to a segfault, perhaps an unrelated issue
   Internal memory fault at 0x8 (IP = +0x34f1a, VMID = 3902099696, TID = 1)

   Prone to hanging - I think a memory corruption issue that may have a pending fix
   recvfrom01,1
   recvfrom01,2

   futex_wait03,1 (see https://github.com/oscarlab/graphene/pull/180#issuecomment-368970338)

   Intermittent seg fault
   kill03,1

   Intermittent hang
   send01,1
   send01,2
   sendto01,1
   sendto01,2
   sendto01,3
   recv01,1
   recv01,2

   Intermittent failure on Linux debug host
   recvmsg01,1
   recvmsg01,2
