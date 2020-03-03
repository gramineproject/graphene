Contributing to Graphene
========================

.. highlight:: sh

.. see Documentation/howto-doc.rst about |nbsp| versus |~|
.. |nbsp| unicode:: 0xa0
   :trim:

First off, thank you for your interest in contributing to Graphene!

In general, code contributions should be submitted to the Graphene project using
a |nbsp| pull request.

Reporting Bugs
--------------

In order to report a |nbsp| problem, please open an issue in the `issue tracker
<https://github.com/oscarlab/graphene/issues>`__.

Architectural Changes
---------------------

Major reorganizations, architectural changes, or code reorganization are best
discussed with the maintainers in advance of writing code. We welcome
contributions, and would hate for anyone to waste time implementing a change
that will not be accepted for a design flaw. It is much better to reach out for
advice first by emailing <support@graphene-project.io>.

Or you can see the archives at this google group:
https://groups.google.com/forum/#!forum/graphene-support

Simple bugfixes need not have advance discussion, but we welcome queries from
newcomers.

Branch Names
------------

For work in progress (for team members), please use your name/userid as
a |nbsp| prefix in the branch name.  For example, if user ``jane`` is adding
feature ``foo``, the branch should be named: ``jane/foo``.

For new contributors, the branch will likely be on a |nbsp| fork of the repository.

Otherwise, branches without this prefix should only be created for
a |nbsp| specific purpose, as approved by the maintainers.

Pull Requests
-------------

The primary mechanism for submitting code changes is with a pull request (PR).

In general, a |nbsp| PR should:

1. Address a single problem; i.e., it should add one feature or fix one issue.
   Fixes for distinct issues should be separated into multiple PRs.
2. Clearly explain the problem and solution in the PR and commit messages, using
   grammatically correct English.
3. Include unit tests for the new behavior or bugfix, except in special
   circumstances, namely: when designing a unit test is difficult (e.g., the
   code is deep enough in Graphene that it would require extra hooks for
   testing) or cannot be easily tested (e.g., a performance fix).
4. Follow project's `style guidelines
   <https://graphene.rtfd.io/en/latest/devel/coding-style.html>`__.

PR Life Cycle
^^^^^^^^^^^^^
1. A PR is created. If the authors know a good candidate for the review (e.g.,
   the author of the specific component) they should assign a suggested reviewer
   on GitHub.
2. From this point on the branch is public, which means that one should ask
   reviewers' permission before doing a force-push.
3. Reviewers shouldn't push commits to the PR, only the authors are allowed to
   do so.
4. Reviewers add comments to the changes.
5. The author discusses the remarks and implements fixes in separate commits.
   Loop to point 4. until all comments are resolved and all reviewers mark the
   PR as approved.
6. The author squashes fix-up commits with original ones, rebases them to
   current master (in case of conflicts) and, if needed and approved by the
   reviewers, does a force-push to share the final version of the changes.
7. The reviewer is responsible for ensuring that the squash is a real squash
   without any additional changes (except resolving conflicts). Only after that
   they can execute rebase+merge to master.

PR Merging Policy
^^^^^^^^^^^^^^^^^
Before a pull request is merged, it must:

1. Pass all CI tests
2. Follow project's `style guidelines
   <https://graphene.rtfd.io/en/latest/devel/coding-style.html>`__.
3. Introduce no new compilation errors or warnings
4. Have all discussions from reviewers resolved
5. Have a clear, concise and grammatically correct comments and commit messages.
6. Have a quorum of approving reviews from maintainers and/or waited an
   appropriate amount of time. This can be:

   - 3 approving reviews
   - 2 approving reviews and 5 days since the PR was created
   - 1 approving review and 10 days since the PR was created, if the author is
     a |nbsp| maintainer

Additional reviews from anyone are welcome.

Reviewing Guidelines
^^^^^^^^^^^^^^^^^^^^
1. All commits must be atomic (i.e., no unrelated changes in the same commit, no
   formatting fixes mixed with features, no moving files and changing them at
   the same time).
2. Meaningful commit messages (it's much easier to get them right if commits are
   really atomic). Should include which component was changed ({Linux,SGX} PAL
   / shim / glibc) in the format "[component] change description".
3. Every PR description should include: what's the purpose of the changes, what
   is changed (and how, in case of redesigning a component), how to test the
   changes.
4. Is it possible to implement this change in a significantly better way?
5. It's C, so check for common problems: correct buffer sizes, integer
   overflows, memory leaks, violations of pointer ownership etc.
6. Verify if all macro parameters are used with additional parentheses.
7. Check for race conditions.
8. Check if all errors are checked and properly handled.
9. Suggest adding assertions (if appropriate). Especially for ensuring
   invariants after a complex operation.
10. Check for possibilities of undefined behaviours (e.g. signed overflow).
11. If the PR fixed a bug, there should be a regression test included in the
    change. The commit containing it should be committed before the fix, so the
    reviewer can easily run it before and after the fix.
12. Code style must follow our guidelines (see below).

Style Guidelines
^^^^^^^^^^^^^^^^
See `style guidelines
<https://graphene.rtfd.io/en/latest/devel/coding-style.html>`__.

Running Regression Tests by Hand
--------------------------------

All of our regression tests are automated in Jenkins jobs (see the
Jenkinsfiles directory), and this is the ultimate documentation for
application-level regression tests, although most tests can be run with
:command:`make regression` or, in the worst case, should have a simple script
called by Jenkins.

We also have (and are actively growing) PAL and shim unit tests.

To run the PAL tests::

   cd Pal/regression
   make regression

For SGX, one needs to do the following::

   cd Pal/regression
   make SGX=1 regression

If a |nbsp| test fails unexpectedly, one can use the :makevar:`KEEP_LOG=1`
option to get the complete output.

One can run tests manually::

   PYTHONPATH=path/to/graphene/Scripts
   PAL_LOADER=path/to/pal-Linux
   export PYTHONPATH PAL_LOADER
   python3 -m pytest -v -rs test_pal.py

It is also possible to run subset of tests::

   # after env export
   python3 -m pytest -v -rs test_pal.py::TC_01_Bootstrap
   python3 -m pytest -v -rs test_pal.py::TC_01_Bootstrap::test_100_basic_boostrapping

The shim unit tests work similarly, and are under
:file:`LibOS/shim/test/regression`.

LTP
^^^
Graphene passes a |nbsp| subset of the LTP tests. New changes should not break
currently passing LTP tests (and, ideally, might add new passing tests). LTP is
currently only supported on the Linux host.

To run these tests::

   cd LibOS/shim/test/apps/ltp
   make
   make ltp.xml
   # or
   make SGX=1 ltp-sgx.xml
   # or manually run the tool with options you need:
   ./runltp_xml.py -c ltp.cfg -v src/runtest/syscalls
