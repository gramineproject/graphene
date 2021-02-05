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


What is Graphene?
=================

Graphene is a |nbsp| lightweight guest OS, designed to run a |nbsp| single
application with minimal host requirements. Graphene can run applications in an
isolated environment with benefits comparable to running a |nbsp| complete OS in
a |nbsp| virtual machine -- including guest customization, ease of porting to
different OSes, and process migration.

Graphene supports native, unmodified Linux applications on any platform.
Currently, Graphene runs on Linux and Intel SGX enclaves on Linux platforms.

With Intel SGX support, Graphene can secure a |nbsp| critical application in
a |nbsp| hardware-encrypted memory region. Graphene can protect applications
from a |nbsp| malicious system stack with minimal porting effort.

Our papers describe the motivation, design choices, and measured performance of
Graphene:

- `EuroSys 2014 <http://www.cs.unc.edu/~porter/pubs/tsai14graphene.pdf>`__
- `ATC 2017 <http://www.cs.unc.edu/~porter/pubs/graphene-sgx.pdf>`__

Graphene is *not a production-ready software* (yet)
===================================================

Graphene is at a point where it is functionally ready for testing and development, but there are
some known security issues that require more attention.  The effort to review and harden security of
Graphene is ongoing.  Our roadmap is to address the remaining production blockers roughly by the fall
of 2021.  Of course, with additional help from the community, we can meet these milestones sooner!

The most important problems (which include major security issues) are tracked in
`#1544 (Production blockers) <https://github.com/oscarlab/graphene/issues/1544>`__.
You should read it before installing and using Graphene.

How to get Graphene?
====================

The latest version of Graphene can be cloned from GitHub::

   git clone https://github.com/oscarlab/graphene.git

At this time Graphene is available only as source code. `Building instructions
are available <https://graphene.readthedocs.io/en/latest/building.html>`__.

How to run an application in Graphene?
======================================

See our `quick start guide <https://graphene.readthedocs.io/en/latest/quickstart.html>`__.

Automatically running applications via Graphene Shielded Containers (GSC)
-------------------------------------------------------------------------

Applications deployed as Docker images may be graphenized via the `gsc tool
<https://graphene.readthedocs.io/en/latest/manpages/gsc.html>`__.

Getting help
============

For the full documentation of the Graphene, see the `Graphene documentation
<https://graphene.readthedocs.io/en/latest/>`__.

For any questions, please send an email to support@graphene-project.io
(`public archive <https://groups.google.com/forum/#!forum/graphene-support>`__).

For bug reports, post an issue on our GitHub repository:
https://github.com/oscarlab/graphene/issues.
