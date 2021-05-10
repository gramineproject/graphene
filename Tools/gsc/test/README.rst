Examples and Tests for GSC
==========================

This folder includes sample images and test cases for GSC:

-  Hello-World (print "Hello World!" using echo)
-  Python3 (run python3 command line) which is tested with a
   ``-c 'print("Hello World!")'`` and the three
   `Graphene Examples <https://github.com/oscarlab/graphene/tree/master/Examples>`__
   from Examples/python
-  NodeJS (print "Hello World")
-  Pytorch script, from
    `Graphene Examples <https://github.com/oscarlab/graphene/tree/master/Examples>`__

Each sample consists of two files ``<distro>-<image-name>.dockerfile`` and
``<distro>-<image-name>.manifest`` where ``<distro>`` specifies the underlying
Linux distribution and ``<image-name>`` specifies the test case. The manifest
file may not exist, since the standard arguments for manifest files often
suffice.

*\*.dockerfile* describes the basic image and its application. It builds the
Docker image by installing required software packages, configuring the
application and changing the Docker entrypoint to start the application.

*\*.manifest* describes the specific Graphene manifest changes required to run
this application reliably. For instance, this includes the memory size and the
number of threads. In some cases this file might be empty, but its existence is
required for the makefile structure.

Building sample images
----------------------

Run::

    make

To build base Docker images named ``<image-name>``::

    make <image-name>

To build a graphenized Docker image of ``<image-name>``::

    make gsc-<image-name>

To build a graphenized image of ``<image-name>`` with additional `gsc build`
arguments (e.g., ``-d``, ``--no-cache``, or ``--rm``)::

    make BUILD_FLAGS=-d gsc-<image-name>

To build the base Docker image named ``<image-name>`` with additional
Docker `build` arguments (e.g., ``--no-cache``, or ``--rm``)::

    make DOCKER_BUILD_FLAGS=--no-cache <image-name>

To sign the graphenized image of ``<image-name>`` with a custom signing key
<your_signing_key.pem>, specify ``KEY_FILE`` (default: ``../enclave_key.pem``)::

    make KEY_FILE=<your_signing_key.pem>

To make a specific distribution, specify ``DISTRIBUTION`` (default:
``ubuntu18.04``)::

    make DISTRIBUTION=ubuntu18.04

To make a specific test case (here ``python3``), specify ``TESTCASES`` (default:
``python3 hello-world nodejs bash numpy pytorch``)

    make TESTCASES=python3

Run sample images with test arguments
-------------------------------------

::

    make test

``make test`` may also be restricted with the ``DISTRIBUTION`` and ``TESTCASES``
arguments.

To run the first ``n`` tests, specify ``MAXTESTNUM``.

::

    make test MAXTESTNUM=<n>

To run a specific test case, specify the test number and distribution.

::

    make test-<test number>-<distribution>

Remove images & containers from Docker daemon
---------------------------------------------

All clean targets can be combined with ``DISTRIBUTION`` and ``TESTCASES`` to
restrict the images to clean.

Remove GSC built sample images::

    make clean-gsc

Remove base sample images::

    make clean-base

Remove containers::

    make clean-containers

Remove all containers built by this test folder (images are kept)::

    make clean
