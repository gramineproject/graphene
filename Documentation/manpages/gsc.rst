.. program:: gsc

============================================
:program:`gsc` -- Graphene Secure Containers
============================================

Synopsis
========

:command:`gsc` *COMMAND* [*OPTION*] ...

Description
===========

Docker containers are widely used to deploy applications in the cloud. Using
Graphene Secure Containers (GSC) we provide the infrastructure to deploy Docker
containers protected by Intel SGX enclaves using the Graphene Library OS.

The :program:`gsc` tool transforms existing Docker images into a new image
(called ``gsc-<image-name>``) which includes the Graphene Library OS, manifest
files, Intel SGX related information, and executes the application inside an
Intel SGX enclave using the Graphene Library OS. It follows the common Docker
approach to first build an image and subsequently run a container of an image.
It provides the :command:`build` command and allows to subsequently use
:command:`docker run`.

Prerequisites
=============

Software packages
-----------------

Please install the docker.io, python3, python3-pip packages. In addition,
install the Docker client python package via pip. GSC required Python 3.6 or
later.

.. code-block:: sh

   sudo apt install docker.io python3 python3-pip
   pip3 install docker pyyaml jinja2

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

.. code-block:: sh

    sudo adduser $USER docker

Create a configuration file called :file:`config.yaml`. Please see the
documentation on configuration options below and use the
:file:`config.yaml.template` as reference.

Command line arguments
======================

.. option:: --help

   Display usage.

.. program:: gsc-build

:command:`gsc build` -- build GSC
---------------------------------

Builds a graphenized Docker image of an application image.

Synopsis:

:command:`gsc build` [*OPTION*] <*IMAGE-NAME*> <*APP1.MANIFEST*> [<*APP2.MANIFEST*> ... <*APPN.MANIFEST*>]

.. option:: -d

   Compile Graphene with debug flags and output

.. option:: -L

   Compile Graphene with Linux PAL in addition to Linux-SGX PAL

.. option:: -G

   Build Graphene only and ignore the application image (useful for Graphene
   development, irrelevant for end users of GSC)

.. option:: IMAGE-NAME

   Name of the application Docker image

.. option:: APP1.MANIFEST

   Application-specific manifest file for the executable entrypoint of the
   Docker image

.. option:: APPN.MANIFEST

   Application-specific Manifest for the n-th application


Application-specific Manifest Files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each application loaded by Graphene requires a separate manifest file.
:program:`gsc` semi-automatically generates these manifest files. It generates a
list of trusted files, assumes values for the number of stacks and memory size,
and generates the chain of trusted children (see below for details). To allow
specializing each application manifest, :program:`gsc` allows the user to
augment each generated manifest. In particular this allows to add additional
trusted or allowed files, and specify a higher memory or number of stacks
requirement.

:program:`gsc` allows application specific manifest files to be empty or not to
exist. In this case :program:`gsc` generates a generic manifest file.

Docker Images starting multiple Applications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Depending on the use case, a Docker container may execute multiple applications.
The Docker image defines the entrypoint application which could fork additional
applications. A common pattern in Docker images executes an entrypoint script
which calls a set of applications. In Graphene the manifest of a parent
application has to specify all trusted children that might be forked.

We define the parent-child relationship by overestimating the set of possible
children. Multiple applications are specified as arguments to :program:`gsc`.
The example below creates a Docker image with three applications. Based on the
specified chain of applications, :program:`gsc` generates parent-child
relationships betweenn application ``appi`` and all applications behind them in
the chain (``> appi``). This overestimates the set of trusted children and may
not map to the actual partent-child relationship. In the example below ``app1``
may call ``app2`` or ``app3``, and ``app2`` may call ``app3``, but ``app2`` may
*not* call ``app1``, and ``app3`` may *not* call ``app1`` or ``app2``.

.. code-block:: sh

   gsc build image app1.manifest app2.manifest app3.manifest

Stages of building graphenized Docker images
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The build process of a graphenized Docker image from image ``<image-name>``
follows two main stages and produces an image named ``gsc-<image-name>``.

.. describe:: Graphene build:

    The first stage compiles Graphene based on the provided configuration (see
    :file:`config.yaml`) which includes the distribution (e.g., Ubuntu18.04) and
    the Intel SGX driver details.

.. describe:: Graphenizing the base image:

    The second stage copies the important Graphene artifacts (e.g., the runtime
    and signer tool) from the first stage. It then prepares image-specific
    variables such as the executable path and the library path, and scanning the
    entire image to generate a list of trusted files. GSC excludes files from
    :file:`/boot`, :file:`/dev`, :file:`/proc`, :file:`/var`, :file:`/sys` and
    :file:`/etc/rc` folders, since checksums are required which either don't
    exist or may vary across different deployment machines. GSC combines these
    values and list of trusted files to a new manifest file. Graphene's signer
    tool generates a SIGSTRUCT file for SGX enclave initialization. This tool
    also generates an SGX-specific manifest file. In a last step the entrypoint
    is changed to launch the :file:`apploader.sh` script which generates an
    Intel SGX token and starts the :program:`pal-Linux-SGX` loader.

Configuration
^^^^^^^^^^^^^

GSC is configured via a configuration file called :file:`config.yaml` with the
following parameters. A template configuration file is provided in
:file:`config.yaml.template`.

.. describe:: Distro:

   Defines Linux distribution to be used to build Graphene in. Currently
   supported value is ``ubuntu18.04``.

.. describe:: Graphene:

   Repository:

      Source repository of Graphene. Default value:
      `https://github.com/oscarlab/graphene
      <https://github.com/oscarlab/graphene>`__

   Branch:

      Use this branch of the repository. Default value: master

.. describe:: SGXDriver:

   Repository:

      Source repository of the Intel SGX driver. Default value:
      `https://github.com/01org/linux-sgx-driver.git
      <https://github.com/01org/linux-sgx-driver.git>`__

   Branch:

      Use this branch of the repository. Default value: sgx_driver_1.9

Run graphenized Docker images
=============================

Execute  :command:`docker run` command via Docker CLI and provide gsgx and
isgx/sgx device, and the PSW/AESM socket. Additional Docker options and
application arguments may be supplied to the  :command:`docker run` command.

.. program:: docker

:command:`docker run` --device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [*OPTIONS*] gsc-<*IMAGE-NAME*>[:<*TAG*>] [<*APPLICATION-ARGUMENTS*>]

.. option:: IMAGE-NAME

   Name of original image (without GSC build).

.. option:: TAG

   Tag of the image to be used.

.. option:: APPLICATION-ARGUMENTS

   Application arguments to be supplied to the application launching inside
   the Docker container and Graphene.

.. option:: OPTIONS

   :command:`docker run` options. Common options include ``-it`` (interactive
   with terminal) or ``-d`` (detached). Please see
   `Docker manual <https://docs.docker.com/engine/reference/commandline/run/>`__
   for details.


Execute with Linux PAL instead of Linux-SGX PAL
-----------------------------------------------

When specifying :option:`-L <gsc-build -L>`  during GSC :command:`gsc build`,
you may select the Linux PAL at Docker run time instead of the Linux-SGX PAL by
specifying the environment variable :envvar:`GSC_PAL` as an option to the
:command:`docker run` command.

.. envvar:: GSC_PAL

   Specifies the pal loader

.. code-block:: sh

    docker run ... --env PAL=Linux gsc-<image-name> ...

Example
=======

The :file:`test` folder in :file:`Tools/gsc` describes how to graphenize Docker
images and test them with sample inputs. The samples include Ubuntu-based Docker
images of Bash, Python, nodejs, Numpy, and Pytorch.

The example below shows how to graphenize the public Docker image of Python3.
This example assumes that all prerequisites are installed and configured.

1. Pull public Python image from Dockerhub:

   .. code-block:: sh

      docker pull python

2. Graphenize the Python image using :program:`gsc`:

   .. code-block:: sh

      cd Tools/gsc
      ./gsc build python test/ubuntu18.04-python3.manifest

3. Test the graphenized Docker image:

   .. code-block:: sh

      docker run --device=/dev/gsgx --device=/dev/*sgx \
         -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
         gsc-python -c 'print("HelloWorld!")'

Limitations
-----------

Dependency on Ubuntu 18.04
^^^^^^^^^^^^^^^^^^^^^^^^^^

Docker images not based on Ubuntu 18.04 may not be compatible with GSC. GSC
relies on Graphene to execute Linux applications inside Intel SGX enclaves and
the installation of prerequisites depends on package manager and package
repositories.

GSC can simply be extended to support other distributions by providing a
template for this distribution in :file:`Tools/gsc/templates`.

Trusted data in Docker volumes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Data mounted as Docker volumes at runtime is not included in the general search
for trusted files during the image build. As a result, Graphene denies access to
these files, since they are neither allowed nor trusted files. This will likely
break applications using files stored in Docker volumes.

Work around:

    Trusted files can be added to image specific manifest file (first argument
    to :command:`gsc build` command) at build time. This work around does not
    allow these files to change between build and run, or over multiple runs.
    This only provides integrity for files and not confidentiality.

Allowing dynamic file contents via Graphene protected file systems:

    Once protected file systems are supported by Graphene, Docker volumes could
    include protected file systems. As a result Graphene can open these
    protected file systems without knowing the exact contents as long as the
    protected file system was specified in the applicaiton-specific manifest.

Integration of Docker Secrets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Docker Secrets are automatically pulled by Docker and the results are stored
either in environment variables or mounted as files. GSC is currently unaware of
such files and hence, cannot mark them trusted. Similar to trusted data, these
files may be added to the application-specific manifest.

Access to files in excluded folders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The manifest generation excludes all files in :file:`/boot`, :file:`/dev`,
:file:`/proc`, :file:`/var`, :file:`/sys`, and :file:`/etc/rc` directories from
the list of trusted files. If your application relies on some files in these
directories, you must manually add them to the application-specific manifest::

    sgx.trusted_file.specialFile=file:PATH_TO_FILE
    or
    sgx.allowed_file.specialFile=file:PATH_TO_FILE

Docker images with non-executables as entrypoint
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Docker images may contain a script entrypoint which is not executable.
:program:`gsc` fails to recognize such entrypoints and fails during the image
build. A workaround relies on creating an image from the application image which
has an entrypoint of the script interpreter with the script as an argument. This
allows :program:`gsc` to start the interpreter instead of the script.
