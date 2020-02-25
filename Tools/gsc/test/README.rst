Examples and Tests for GSC
==========================

This folder includes sample images and test cases for GSC:

-  Hello-World (print "Hello World!" using echo)
-  Python3 (run python3 command line) which is tested with a
   ``-c 'print("Hello World!")'`` and the three `Graphene
   test <https://github.com/oscarlab/graphene-tests>`__ scripts from
   python-simple

Each sample consists of two files ``<distro>-<image-name>.dockerfile``
and ``<distro>-<image-name>.manifest`` where ``<distro>`` specifies the
underlying Linux distribution and ``<image-name>`` specifies the test
case.

**\*.dockerfile** describes the basic image and its application. It
builds the Docker image by installing required software packages,
configuring the application and changing the Docker entrypoint to start
the application.

**\*.manifest** describes the specific Graphene manifest changes
required to run this application reliably. For instance, this includes
the memory size and the number of threads. In some cases this file might
be empty, but its existence is required for the makefile structure.

Building sample images
----------------------

Run::

    make

To build base images named ``<image-name>``::

    make <image-name>

To build a graphenized image named ``<image-name>``::

    make gsc-<image-name>

Run sample images with test arguments
-------------------------------------

::

    make test

Remove images & containers from Docker daemon
---------------------------------------------

Remove GSC built sample images::

    make cleanGSC

Remove base sample images::

    make cleanBase

Remove containers::

    make cleanContainers

Remove all containers built by this test folder (images are kept)::

    make clean

Remove all images and containers built by this test folder::

    make distclean
