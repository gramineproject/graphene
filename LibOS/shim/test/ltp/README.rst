LTP FOR GRAPHENE
================

Just run ``make regression``, or ``make SGX=1 regression``.

Test results are reported as an XML file, ``ltp.xml`` or ``ltp-sgx.xml``, which
is for consumption in Jenkins. There is also rudimentary logging.

To run a single testcase, execute the following commands::

    cd <LTP_REPO>/install/testcases/bin/
    graphene-{direct|sgx} <TEST_BINARY>

In this way, one can debug one particular syscall testcase.

To get more information, you can:

- Enable debugging output: edit ``/install/testcases/bin/manifest`` to set
  ``loader.log_level = "trace"``. Note that you will need to revert this
  change for ``make regression`` to work correctly. This will also not work when
  running under SGX, because the manifest needs to be re-signed afterwards.

- Use GDB: ``GDB=1 graphene-{direct|sgx} <TEST_BINARY>``. You should compile
  Graphene with ``DEBUG=1`` so that you can see the symbols inside Graphene.

Running all the cases
---------------------

In case you want to analyze all the test results, including the tests that are
currently skipped, you can use the ``ltp-all.cfg`` configuration::

    ./runltp_xml.py -v -c ltp-all.cfg install/runtest/syscalls -O ltp-all.xml

The ``all.xml`` file should contain output for all tests.

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

SGX mode
--------

In SGX mode, we use additional files: ``ltp-sgx.cfg``, and (temporarily)
``ltp-bug-1075.cfg``. These function as an override for ``ltp.cfg``, so that
configuration is not duplicated.

Helper scripts (``contrib/``)
-----------------------------

The ``contrib/`` directory contains a few scripts for dealing with ``.cfg``
files. Except for ``conf_lint.py``, they are used for manual and one-off tasks.

* ``conf_lint.py``: Validate the configuration (check if it's sorted, look for
  outdated test names). Used in ``make regression``.

* ``conf_merge.py``: Merge two ``.cfg`` files. If there are duplicate section
  names, concatenate the sections.

* ``conf_missing.py``: Add missing sections to a ``.cfg`` file, so that it
  contains sections for all tests (based on an LTP scenario file with a list of
  tests).

* ``conf_remove_must_pass.py``: Remove all sections with ``must-pass``
  directive.

* ``conf_subtract.py``: Generate a difference between two files, i.e. output all
  sections that are in the second file but not in the first. This effectively
  converts a "full" configuration to an "override" one.
