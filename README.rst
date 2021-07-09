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

Release candidate version of Graphene 1.2 available
===================================================

Graphene has evolved a |nbsp| lot since our last major release. Over the last
few months, we have made significant updates to provide a |nbsp| stable version
that supports deploying key workloads with Intel SGX. We’ve rewritten major
subsystems, done a |nbsp| significant update to the build and packaging
scripts, extended test coverage, and improved the CI/CD process. We’ve reviewed
and hardened specific security aspects of Graphene, and increased stability for
long-running and heavy workloads.

Graphene also includes full SGX Attestation support, protected files support,
multi-process support with encrypted IPC, and support for the upstreamed SGX
driver for Linux. We’ve introduced a |nbsp| number of performance optimizations
for SGX, and provide mechanisms to more easily deploy in cloud environments
with full support for automatic Docker container integration using Graphene
Shielded Containers (GSC).

We have a |nbsp| growing set of well-tested applications including machine
learning frameworks, databases, webservers, and programming language
runtimes.

This version of Graphene is tagged 'v1.2-rc1'. We encourage you to try this out
with your workloads and let us know if you’re facing any issues. Please see
`the release page
<https://github.com/oscarlab/graphene/releases/tag/v1.2-rc1>`__ for release
notes and installation instructions.

While we have made significant progress, we are continuing to work towards
making Graphene better and adding support for more workloads. The items that we
are most immediately working on are tracked in `#1544
<https://github.com/oscarlab/graphene/issues/1544>`__.

In the meantime, we are also in the process of transitioning the Graphene
project to a |nbsp| new home within the Confidential Computing Consortium under
the Linux Foundation. In Q3 2021 we will provide more details on this, and we
expect the next version of Graphene to be released once this transition is
complete.

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
