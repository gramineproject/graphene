.. program:: gsc

==================================================================
:program:`gsc` -- Graphene Secure Containers
==================================================================

Synopsis
========

:command:`gsc` *COMMAND* [*OPTION*] ...

Description
===========

Docker containers are widely used to deploy applications in the cloud. Using
Graphene Secure Containers (GSC) we provide the infrastructure to deploy Docker
containers protected by Intel SGX enclaves using the Graphene Library OS.

The ``gsc`` tool transforms existing Docker images into a new image (called
``gsc-<image-name>``) which includes the Graphene Library OS, manifest files,
Intel SGX related information, and executes the application inside an Intel SGX
enclave using the Graphene Library OS. It follows the common Docker approach to
first build an image and subsequently run a container of an image. It provides
the ``build`` command and allows to subsequently use ``docker run``.

Prerequisites
======================

Software packages
-----------------

Please install the docker.io, python3, python3-pip packages. In addition,
install the Docker client python package via pip.

.. code-block:: bash

   sudo apt install docker.io python3 python3-pip
   pip3 install docker

Kernel Modules and Services
---------------------------

To run Intel SGX applications, please install the following kernel driver and
services.

- `Intel SGX driver <https://github.com/intel/linux-sgx-driver>`__
- `Intel SGX SDK <https://01.org/intel-software-guard-extensions/downloads>`__
- `Graphene SGX Driver (kernel module) <https://github.com/oscarlab/graphene-sgx-driver>`__

Host Configuration
------------------

To create Docker images, the user must have access to Docker daemon.

.. code-block:: bash

    sudo adduser $USER docker

Create a configuration file called ``config.json``. Please see the documentation
on configuration options below and use the ``config.json.template`` as
reference.

Command line arguments
======================

Commands
--------

.. option:: help

   Display usage.

.. option:: build

   Synopsis:

   :command:`gsc build` [*OPTION*] <*IMAGE-NAME*> <*APP1.MANIFEST*> [<*APP2.MANIFEST*> ... <*APPN.MANIFEST*>]

   Builds graphenized Docker image of application image `image-name`.

   .. option:: IMAGE-NAME

      Name of the application Docker image

   .. option:: APP1.MANIFEST

      Application-specific manifest file for the executable entrypoint of the
      Docker image

   .. option:: APPN.MANIFEST

      Application-specific Manifest for the n-th application

   Possible ``build`` options:

      .. option:: -d

      Compile Graphene with debug flags and output

      .. option:: -L

      Compile Graphene with Linux PAL in addition to Linux-SGX PAL

      .. option:: -G

      Build Graphene only and ignore the application image (useful for Graphene
      development, irrelevant for end users of GSC)

**Application-specific Manifest Files**

Each application loaded by Graphene requires a separate manifest file. ``gsc``
semi-automatically generates these manifest files. It generates a list of
trusted files, assumes values for the number of stacks and memory size, and
generates the chain of trusted children (see below for details). To allow
specializing each application manifest, ``gsc`` allows the user to augment each
generated manifest. In particular this allows to add additional trusted or
allowed files, and specify a higher memory or number of stacks requirement.

``gsc`` allows application specific manifest files to be empty or not to exist.
In this case ``gsc`` generates a generic manifest file.

**Docker Images starting multiple Applications**

Depending on the use case, a Docker container may execute multiple applications.
The Docker image defines the entrypoint application which could fork additional
applications. A common pattern in Docker images executes an entrypoint script
which calls a set of applications. In Graphene the manifest of a parent
application has to specify all trusted children that might be forked.

We define the parent-child relationship by overestimating the set of possible
children. Multiple applications are specified as arguments to ``gsc``. The
example below creates a Docker image with three applications. Based on the
specified chain of applications, ``gsc`` generates parent-child relationships
betweenn application ``appi`` and all applications behind them in the chain (``>
appi``). This overestimates the set of trusted children and may not map to the
actual partent-child relationship. In the example below ``app1`` may call
``app2`` or ``app3``, and ``app2`` may call ``app3``, but ``app2`` may *not*
call ``app1``, and ``app3`` may *not* call ``app1`` or ``app2``.

.. code-block:: bash

   gsc build image app1.manifest app2.manifest app3.manifest

**Configuration**

GSC is configured via a configuration file called ``config.json`` with the
following parameters.

   .. option:: distro

      Defines Linux distribution to be used to build Graphene in. Currently
      supported values are ``ubuntu18.04``/``ubuntu16.04``.

   .. option:: graphene_repository

      Source repository of Graphene. Default value:
      https://github.com/oscarlab/graphene

   .. option:: graphene_branch

      Branch of the ``graphene_repository``. Default value: master

   .. option:: sgxdriver_repository

      Source repository of the Intel SGX driver. Default value:
      https://github.com/01org/linux-sgx-driver.git

   .. option:: sgxdriver_branch

      Branch of the ``sgxdriver_repository``. Default value: sgx_driver_1.9

Run graphenized Docker images
=============================

Execute Docker run command via Docker CLI and provide gsgx and isgx/sgx device,
and the PSW/AESM socket. Additional Docker options and application arguments may
be supplied to the Docker run command.

.. program:: docker

:command:`docker` run --device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [*OPTIONS*] gsc-<*IMAGE-NAME*>[:<*TAG*>] [<*APPLICATION-ARGUMENTS*>]

   .. option:: IMAGE-NAME

      Name of original image (without GSC build).

   .. option:: TAG

      Tag of the image to be used.

   .. option:: APPLICATION-ARGUMENTS

      Application arguments to be supplied to the application launching inside
      the Docker container and Graphene.

   .. option:: OPTIONS

      Docker run options. Common options include ``-it`` (interactive with
      terminal) or ``-d`` (detached). Please see
      `Docker manual <https://docs.docker.com/engine/reference/commandline/run/>`__
      for details.


Execute with Linux PAL instead of Linux-SGX PAL
-----------------------------------------------

When specifying ``-L`` during GSC ``build``, you may select the Linux PAL at
Docker run time instead of the Linux-SGX PAL by specifying the environment
variable ``LINUX_PAL`` as an option to the Docker ``run`` command.

.. code-block:: bash

    docker run ... --env LINUX_PAL=linux gsc-<image-name> ...

Example
=======

This example shows how to graphenize the public Docker image of Python3. This
example assumes that all prerequisites are installed and configured. For more
examples refer to the test folder of ``gsc``.

1) Pull public Python image from Dockerhub:

.. code-block:: bash

   docker pull python

2) Graphenize the Python image using ``gsc``:

.. code-block:: bash

   cd Tools/gsc
   gsc build python test/ubuntu18.04-python3.manifest

3) Test the graphenized Docker image:

.. code-block:: bash

   docker run --device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket python -c 'print("HelloWorld!")'