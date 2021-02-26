Contributing to Graphene
========================

.. highlight:: sh

.. see Documentation/howto-doc.rst about |nbsp| versus |~|
.. |nbsp| unicode:: 0xa0
   :trim:

First off, thank you for your interest in contributing to Graphene!

In general, code contributions should be submitted to the Graphene project
using a |nbsp| `pull request <https://github.com/oscarlab/graphene/pulls>`__.

Reporting Bugs
--------------

In order to report a |nbsp| problem, please open an issue in the `issue tracker
<https://github.com/oscarlab/graphene/issues>`__.

Reporting Security Vulnerabilities
----------------------------------

Currently, we aren't aware of any production usage of Graphene, so feel free to
report them using GitHub issues. Please note that this guideline may change
quite soon, so please always check it before publicly reporting any
vulnerabilities.

Architectural Changes
---------------------

Major reorganizations, architectural changes, or code reorganization are best
discussed with the maintainers in advance of writing code. We welcome
contributions, and would hate for anyone to waste time implementing a change
that will not be accepted for a design flaw. It is much better to reach out for
advice first by emailing support@graphene-project.io.

Or you can see the archives at this google group:
https://groups.google.com/forum/#!forum/graphene-support

Please verify that your change doesn't introduce any insecure-by-default
functionality. If an option allows users to introduce a security risk, the
option should have a name prefixed with ``insecure__`` and be disabled by
default.

Simple bugfixes need not have advance discussion, but we welcome queries from
newcomers.

Branch Names
------------

For work in progress (for team members), please use your name/userid as
a |nbsp| prefix in the branch name.  For example, if user ``jane`` is adding
feature ``foo``, the branch should be named: ``jane/foo``.

For new contributors, the branch will likely be on a |nbsp| fork of the
repository.

Otherwise, branches without this prefix should only be created for
a |nbsp| specific purpose, as approved by the maintainers.

Pull Requests
-------------

The primary mechanism for submitting code changes is with a pull request (PR).

In general, a |nbsp| PR should:

#. Address a single problem.
#. Clearly explain the problem and solution in the PR and commit messages, using
   grammatically correct American English.
#. Include unit tests for the new behavior or bugfix, except in special
   circumstances, namely: when designing a unit test is difficult (e.g., the
   code is deep enough in Graphene that it would require extra hooks for
   testing) or cannot be easily tested (e.g., a performance fix).
#. Follow project's `style guidelines
   <https://graphene.rtfd.io/en/latest/devel/coding-style.html>`__.
#. Be signed-off by the author of the PR in git (i.e., using the ``git commit -s``, indicating
   that the authors are agreeing to the terms of the `project Developer
   Certificate of Origin <DCO>`__

.. Github and RTD use different roots for resolving paths, because of
   of .. include: in Documentation/devel/contributing.rst.  This renders as
   a directory over file//.  Over http[s]:// we take advantage of the automatic
   / redirect implemented in most HTTP servers. That's why DCO/ is a directory and not a file.

PR Life Cycle
^^^^^^^^^^^^^
We use git-rebase workflow and Reviewable.io for reviews.

TL;DR: Merge commits are never allowed and force-pushes are not allowed after a
review has started. Before merging, commits will be cleaned up, rebased onto the
current master and tested again in CI.

Detailed explanation:

#. A PR is created. If the authors know a good candidate for the review (e.g.,
   the author of the specific component) they should assign a suggested reviewer
   on GitHub.
#. From this point on the branch is public, which means that one should ask
   reviewers' permission before doing a force-push.
#. Reviewers shouldn't push commits to the PR, only the authors are allowed to
   do so.
#. Reviewers add comments to the changes using Reviewable.io integration.
#. The author discusses the remarks and implements fixes in separate commits
   (ideally, using ``git commit --fixup``). Loop to point 4. until the PR is
   approved (see :ref:`merging_policy`).
#. One of the maintainers squashes fix-up commits with original ones, rebases
   the branch onto the current master and force-pushes the branch to GitHub to
   share.

.. _merging_policy:

PR Merging Policy
^^^^^^^^^^^^^^^^^
Before a pull request is merged, it must:

#. Pass all CI tests
#. Follow project's `style guidelines
   <https://graphene.rtfd.io/en/latest/devel/coding-style.html>`__.
#. Be signed-off by the contributor.
#. Introduce no new compilation errors or warnings
#. Have all discussions from reviewers resolved
#. Have a clear, concise and grammatically correct comments and commit messages.
#. Have a quorum of approving reviews from maintainers and/or waited an
   appropriate amount of time. This can be:

   - 3 approving maintainers
   - 2 approving maintainers and 5 days since the PR was created

   If the author is a |nbsp| maintainer the limits are lowered by 1.

Additional reviews from anyone are welcome.

Reviewing Guidelines
^^^^^^^^^^^^^^^^^^^^
#. All commits must be atomic (i.e., no unrelated changes in the same commit, no
   formatting fixes mixed with features, no moving files and changing them at
   the same time).
#. Meaningful commit messages (it's much easier to get them right if commits are
   really atomic). Should include which component was changed (Pal-{Linux,SGX}
   / LibOS / Docs / CI) in the format "[component] change description".
#. Every PR description should include: what's the purpose of the changes, what
   is changed (and how, in case of redesigning a component), and how to test the
   changes.
#. Is it possible to implement this change in a significantly better way?
#. It's C, so check for common problems: correct buffer sizes, integer
   overflows, memory leaks, violations of pointer ownership etc.
#. Verify if all macro parameters are used with additional parentheses.
#. Check for race conditions.
#. Check if all errors are checked and properly handled.
#. Suggest adding assertions (if appropriate). Especially for ensuring
   invariants after a complex operation.
#. Check for possibilities of undefined behaviours (e.g. signed overflow).
#. If the PR fixed a bug, there should be a regression test included in the
   change. The commit containing it should be committed before the fix, so the
   reviewer can easily run it before and after the fix.
#. Code style must follow our guidelines (see below).

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

One can run tests manually (prepend the command with ``SGX=1`` or
``PAL_HOST=Linux-SGX`` to run the SGX variant)::

   /path/to/graphene/Scripts/run-pytest -v -rs test_pal.py
   SGX=1 /path/to/graphene/Scripts/run-pytest -v -rs test_pal.py

It is also possible to run subset of tests::

   /path/to/graphene/Scripts/run-pytest -v -rs test_pal.py::TC_01_Bootstrap
   /path/to/graphene/Scripts/run-pytest -v -rs test_pal.py::TC_01_Bootstrap::test_100_basic_boostrapping

The ``run-pytest`` script is a wrapper for `pytest
<https://docs.pytest.org/en/stable/usage.html>`__ and accepts the same
command-line options.

The shim unit tests work similarly, and are under
:file:`LibOS/shim/test/regression`.

LTP
^^^
Graphene passes a |nbsp| subset of the LTP tests. New changes should not break
currently passing LTP tests (and, ideally, might add new passing tests). LTP is
currently only supported on the Linux PAL.

To run these tests::

   cd LibOS/shim/test/ltp
   make
   make ltp.xml
   # or
   make SGX=1 ltp-sgx.xml
   # or manually run the tool with options you need:
   ./runltp_xml.py -c ltp.cfg -v src/runtest/syscalls


Management Team
===============

The current members of the management team are:

* Michał Kowalczyk (Invisible Things Lab/Golem)
* Dmitrii Kuvaiskii (Intel)
* Borys Popławski (Invisible Things Lab/Golem)
* Don Porter (UNC)
* Chia-Che Tsai (Texas A&M University)
* Rafał Wojdyła (Invisible Things Lab/Golem)
* Mona Vij (Intel)
* Isaku Yamahata (Intel)

The procedure for adding and removing maintainers
-------------------------------------------------

+ Joining: # of PRs submitted & merged + # of PRs reviewed + # of issues closed
  >= 20 (this means that a PR which fixes 3 issues counts as 4). Only complete
  and thorough reviews count.
+ Leaving: a member may be removed if not active or notoriously breaking rules
  from this document.
+ Additionally, at least 60% (rounded up) of current members have to agree to
  make any change to the team membership.
