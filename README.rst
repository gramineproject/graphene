******************************************
Graphene Library OS with Intel SGX Support
******************************************

.. image:: https://readthedocs.org/projects/graphene/badge/?version=latest
   :target: http://graphene.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

*A Linux-compatible Library OS for Multi-Process Applications*

.. This is not |~|, because that is in rst_prolog in conf.py, which GitHub cannot parse.
   GitHub doesn't appear to use it correctly anyway...
.. |nbsp| unicode:: 0xa0
   :trim:

.. highlight:: sh

**NOTE:** We are in the middle of transitioning our buildsystem to Meson, and
the build procedures are changing. See `Building instructions
<https://graphene.readthedocs.io/en/latest/building.html>`__ for an up-to-date
build tutorial.

What is Graphene?
=================

Graphene is a |nbsp| lightweight library OS, designed to run a single
application with minimal host requirements. Graphene can run applications in an
isolated environment with benefits comparable to running a |nbsp| complete OS in
a |nbsp| virtual machine -- including guest customization, ease of porting to
different OSes, and process migration.

Graphene supports native, unmodified Linux binaries on any platform. Currently,
Graphene runs on Linux and Intel SGX enclaves on Linux platforms.

In untrusted cloud and edge deployments, there is a |nbsp| strong desire to
shield the whole application from rest of the infrastructure. Graphene supports
this “lift and shift” paradigm for bringing unmodified applications into
Confidential Computing with Intel SGX. Graphene can protect applications from a
|nbsp| malicious system stack with minimal porting effort.

Graphene is a growing project and we have a growing contributor and maintainer
community. The code and overall direction of the project are determined by a
diverse group of contributors, from universities, small and large companies, as
well as individuals. Our goal is to continue this growth in both contributions
and community adoption.

Working towards production ready Graphene by Q2’21
==================================================

Graphene has evolved a |nbsp| lot since our last major release and at this point
we have significantly reworked most of the research code towards building a
|nbsp| production ready Graphene by end of Q2’21. We have a |nbsp| growing set
of well tested applications including machine learning frameworks, databases,
webservers, and programming language runtimes.

Graphene also supports many features for deploying secure solutions with SGX.
These include full SGX Attestation support (EPID/DCAP), protected files support,
and multi-process support with encrypted IPC. Graphene also supports a |nbsp|
number of performance optimizations for SGX including support for asynchronous
system calls.

Graphene is ready to be deployed in cloud environments with full support for
automatic container integration, using Graphene Shielded Containers (GSC).

We have been actively developing, testing, and validating Graphene. The effort
to review and harden security of Graphene is ongoing.

The most important problems (which include major security issues) are tracked in
`#1544 (Production blockers) <https://github.com/oscarlab/graphene/issues/1544>`__.
Our roadmap is to address the majority of the remaining production blockers by
Q2’21 and rest will follow in future releases.

Graphene documentation
======================

The official Graphene documentation can be found at
https://graphene.readthedocs.io. Below are quick links to some of the most
important pages:

- `Quick start and how to run applications
  <https://graphene.readthedocs.io/en/latest/quickstart.html>`__
- `Complete building instructions
  <https://graphene.readthedocs.io/en/latest/building.html>`__
- `Graphene manifest file syntax
  <https://graphene.readthedocs.io/en/latest/manifest-syntax.html>`__
- `The Graphene Shielded Containers (GSC) tool
  <https://graphene.readthedocs.io/en/latest/manpages/gsc.html>`__
- `Performance tuning & analysis of SGX applications in Graphene
  <https://graphene.readthedocs.io/en/latest/devel/performance.html>`__
- `Remote attestation in Graphene
  <https://graphene.readthedocs.io/en/latest/attestation.html>`__


Getting help
============

For any questions, please send an email to support@graphene-project.io
(`public archive <https://groups.google.com/forum/#!forum/graphene-support>`__).

For bug reports, post an issue on our GitHub repository:
https://github.com/oscarlab/graphene/issues.


Acknowledgments
===============

Graphene Project benefits from generous help of `fosshost.org
<https://fosshost.org>`__: they lend us a VPS, which we use as toolserver and
package hosting.
