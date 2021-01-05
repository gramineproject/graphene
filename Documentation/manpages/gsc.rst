.. program:: gsc

==============================================
:program:`gsc` -- Graphene Shielded Containers
==============================================

.. warning::
    GSC is still under development and must not be used in production! Please
    see `issue #1520 <https://github.com/oscarlab/graphene/issues/1520>`__ for a
    description of missing features and security caveats.

Synopsis
========

:command:`gsc` *COMMAND* [*OPTIONS*] ...

Description
===========

Docker containers are widely used to deploy applications in the cloud. Using
Graphene Shielded Containers (GSC) we provide the infrastructure to deploy Docker
containers protected by Intel SGX enclaves using the Graphene Library OS.

The :program:`gsc` tool transforms a Docker image into a new image
(called ``gsc-<image-name>``) which includes the Graphene Library OS, manifest
files, Intel SGX related information, and executes the application inside an
Intel SGX enclave using the Graphene Library OS. It follows the common Docker
approach to first build an image and subsequently run a container of an image.
At first a Docker image has to be graphenized via the :command:`gsc build`
command. When the graphenized image should run within an Intel SGX enclave, the
image has to be signed via a :command:`gsc sign-image` command. Subsequently,
the image can be run using :command:`docker run`.

Prerequisites
=============

The installation descriptions of prerequisites are for Ubuntu 18.04 and may
differ when using a different Ubuntu version or Linux distribution.

Software packages
-----------------

Please install the ``docker.io``, ``python3``, ``python3-pip`` packages. In
addition, install the Docker client python package via pip. GSC requires Python
3.6 or later.

.. code-block:: sh

   sudo apt install docker.io python3 python3-pip
   pip3 install docker pyyaml jinja2

Kernel modules and services
---------------------------

To run with Intel SGX, please install the following kernel driver and
services:

- `Intel SGX driver <https://github.com/intel/linux-sgx-driver>`__
- `Intel SGX SDK <https://01.org/intel-software-guard-extensions/downloads>`__
- `Graphene SGX Driver (kernel module) <https://github.com/oscarlab/graphene-sgx-driver>`__

Host configuration
------------------

To create Docker images, the user must have access to Docker daemon.

.. warning::
    Please use this step with caution. By granting the user access to the Docker
    group, the user may acquire root privileges via :command:`docker run`. You
    could also run commands as root.

.. code-block:: sh

   sudo adduser $USER docker

Create a configuration file called :file:`config.yaml` or specify a different
configuration file via :program:`gsc` option. Please see the documentation on
configuration options below and use the :file:`config.yaml.template` as
reference.

Command line arguments
======================

.. option:: --help

   Display usage.

.. program:: gsc-build

:command:`gsc build` -- build graphenized image
-----------------------------------------------

Builds an unsigned graphenized Docker image of an application image called
``gsc-<IMAGE-NAME>-unsigned`` by compiling Graphene or relying on a prebuilt
Graphene image.

Synopsis:

:command:`gsc build` [*OPTIONS*] <*IMAGE-NAME*> <*APP1.MANIFEST*> [<*APP2.MANIFEST*> ... <*APPN.MANIFEST*>]

.. option:: -d

   Compile Graphene with debug flags and debug output. If configured to use a
   prebuilt Graphene image, the image has to support this option.

.. option:: -L

   Compile Graphene with Linux PAL in addition to Linux-SGX PAL. If configured
   to use a prebuilt Graphene image, the image has to support this option.

.. option:: --insecure-args

   Allow untrusted arguments to be specified at :command:`docker run`. Otherwise
   any arguments specified during :command:`docker run` are ignored.

.. option:: -nc

   Disable Docker's caches during :command:`gsc build`. This builds the
   unsigned graphenized image from scratch.

.. option:: --rm

   Remove intermediate Docker images created by :command:`gsc build`, if the
   image build is successful.

.. option:: --build-arg

   Set build-time variables during :command:`gsc build` (same as `docker build
   --build-arg`).

.. option:: -c

   Specify configuration file. Default: :file:`config.yaml`.

.. option:: IMAGE-NAME

   Name of the application Docker image.

.. option:: APP.MANIFEST

   Manifest file (Graphene configuration).

.. program:: gsc-sign-image

:command:`gsc sign-image` -- signs a graphenized image
------------------------------------------------------

Signs the enclave of an unsigned graphenized Docker image and creates a new
Docker image called ``gsc-<IMAGE-NAME>``. :command:`gsc sign-image` always
removes intermediate Docker images, if successful or not, to ensure the removal
of the signing key in intermediate Docker images.

Synopsis:

:command:`gsc sign-image` [*OPTIONS*] <*IMAGE-NAME*> <*KEY-FILE*>

.. option:: -c

   Specify configuration file. Default: :file:`config.yaml`

.. option:: IMAGE-NAME

   Name of the application Docker image

.. option:: KEY-FILE

   Used to sign the Intel SGX enclave

.. program:: gsc-build-graphene

:command:`gsc build-graphene` -- build Graphene-only Docker image
-----------------------------------------------------------------

Builds a base Docker image including the Graphene sources and compiled runtime.
This base image can be used as input for :command:`gsc build` via configuration
parameter `Graphene.Image`.

Synopsis:

:command:`gsc build-graphene` [*OPTIONS*] <*IMAGE-NAME*>

.. option:: -d

   Compile Graphene with debug flags and debug output. Allows :command:`gsc
   build` commands to include debug runtime using :option:`-d <gsc-build -d>`.

.. option:: -L

   Compile Graphene with Linux PAL in addition to Linux-SGX PAL. Allows
   :command:`gsc build` commands to include the Linux PAL using :option:`-L
   <gsc-build -L>`.

.. option:: -nc

   Disable Docker's caches during :command:`gsc build-graphene`. This builds the
   unsigned graphenized image from scratch.

.. option:: --rm

   Remove intermediate Docker images created by :command:`gsc build-graphene`,
   if the image build is successful.

.. option:: --build-arg

   Set build-time variables during :command:`gsc build-graphene` (same as
   `docker build --build-arg`).

.. option:: -c

   Specify configuration file. Default: :file:`config.yaml`

.. option:: -f

   Stop after Dockerfile is created and do not build the Docker image.

.. option:: IMAGE-NAME

   Name of the resulting Graphene Docker image


Using Graphene's trusted command line arguments
-----------------------------------------------

Most executables aren't designed to run with attacker-controlled arguments.
Allowing an attacker to control executable arguments can break the security of
the resulting enclave.

:command:`gsc build` uses the existing Docker image's entrypoint and cmd fields
to identify the trusted arguments. These arguments are stored in
:file:`trusted_argv`. This file is only generated when :option:`--insecure-args
<gsc-build --insecure-args>` is *not* specified. As a result any arguments
specified during :command:`docker run` are ignored.

To be able to provide arguments at runtime, the image build has to enable this
via the option :option:`--insecure-args <gsc-build --insecure-args>`.

Docker images starting multiple applications
--------------------------------------------

Depending on the use case, a Docker container may execute multiple applications.
The Docker image defines the entrypoint executable which could fork additional
executables. A common pattern in Docker images is executing an entrypoint script
which calls a set of executables. Similarly to Docker, Graphene has a
corresponding option (``libos.entrypoint``) which should point to the first
executable started inside Graphene namespace.

Stages of building graphenized SGX Docker images
------------------------------------------------

The build process of a graphenized Docker image from image ``<image-name>``
follows four main stages and produces an image named ``gsc-<image-name>``.
:command:`gsc build` generates the first two stages (building/pulling Graphene
and graphenizing the base image) and :command:`gsc sign-image` generates the
last two stages (signing the Intel SGX enclave and generating the final Docker
image).

Building or Pulling Graphene
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first stage either compiles Graphene based on the provided configuration
(see :file:`config.yaml`) which includes the distribution (e.g., Ubuntu 18.04),
Graphene repository, and the Intel SGX driver details, or pulls a prebuilt
Docker image also defined via the configuration file. Prebuilt images will be
provided for popular cloud-provider offerings or can be created via
:command:`gsc build-graphene`.

Graphenizing the application image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The second stage copies the important Graphene artifacts (e.g., the runtime and
signer tool) from the first stage. It then prepares image-specific variables
such as the executable path and the library path, and scans the entire image to
generate a list of trusted files. GSC excludes files and paths starting with
:file:`/boot`, :file:`/dev`, :file:`/proc`, :file:`/var`, :file:`/sys` and
:file:`/etc/rc`, since checksums are required which either don't exist or may
vary across different deployment machines. GSC combines these variables and list
of trusted files to a new manifest file. In a last step the entrypoint is
changed to launch the :file:`apploader.sh` script which generates an Intel SGX
token and starts the :program:`pal-Linux-SGX` loader. The generated image
(``gsc-<image-name>-unsigned``) cannot successfully load an Intel SGX enclave,
since essential files and the signing of the enclave are missing.

Signing the Intel SGX enclave
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The third stage uses Graphene's signer tool to generate SIGSTRUCT files for SGX
enclave initialization. This tool also generates an SGX-specific manifest files.
The required signing key is provided by the user via the :command:`gsc
sign-image` command and copied into this Docker build stage.

Generating a signed graphenized Docker image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The last stage combines the graphenized Docker image with the signed enclave and
manifest files. Therefore it copies the SIGSTRUCT files and the SGX-specific
manifest file from the previous stage into the graphenized Docker image from the
second stage. The resulting image is called `gsc-<image-name>` and includes all
necessary files to start an Intel SGX enclave.

Configuration
=============

GSC is configured via a configuration file called :file:`config.yaml` or
specified as a :program:`gsc` option. A template configuration file is provided
in :file:`config.yaml.template`.

.. describe:: Distro

   Defines Linux distribution to be used to build Graphene in. Currently the
   only supported value is ``ubuntu18.04``.

.. describe:: Graphene.Repository

   Source repository of Graphene. Default value:
   `https://github.com/oscarlab/graphene.git
   <https://github.com/oscarlab/graphene.git>`__

.. describe:: Graphene.Branch

   Use this branch of the repository. Default value: master

.. describe:: Graphene.Image

   Builds graphenized Docker image based on a prebuilt Graphene Docker image.
   These images are prepared via :command:`gsc build-graphene` and will be
   provided for popular cloud-provider environments. `Graphene.Repository` and
   `Graphene.Branch` are ignored in case `Graphene.Image` is specified.

.. describe:: SGXDriver.Repository

   Source repository of the Intel SGX driver. Default value:
   `https://github.com/01org/linux-sgx-driver.git
   <https://github.com/01org/linux-sgx-driver.git>`__

.. describe:: SGXDriver.Branch

   Use this branch of the repository. Default value: sgx_driver_1.9

Run graphenized Docker images
=============================

Execute :command:`docker run` command via Docker CLI and provide gsgx and
isgx/sgx device, and the PSW/AESM socket. Additional Docker options and
executable arguments may be supplied to the :command:`docker run` command.

.. warning::
   Forwarding devices to a container lowers security of the host. GSC should
   never be used as a sandbox for applications (i.e. it only shields the app
   from the host but not vice versa).

.. program:: docker

:command:`docker run` --device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [*OPTIONS*] gsc-<*IMAGE-NAME*> [<*ARGUMENTS*>]

.. option:: OPTIONS

   :command:`docker run` options. Common options include ``-it`` (interactive
   with terminal) or ``-d`` (detached). Please see
   `Docker manual <https://docs.docker.com/engine/reference/commandline/run/>`__
   for details.

.. option:: IMAGE-NAME

   Name of original image (without GSC build).

.. option:: ARGUMENTS

   Arguments to be supplied to the executable launching inside the Docker
   container and Graphene. Such arguments may only be provided when
   :option:`--insecure-args <gsc-build --insecure-args>` was specified during
   :command:`gsc build`.


Execute with Linux PAL instead of Linux-SGX PAL
-----------------------------------------------

When specifying :option:`-L <gsc-build -L>`  during GSC :command:`gsc build`,
you may select the Linux PAL at Docker run time instead of the Linux-SGX PAL by
specifying the environment variable :envvar:`GSC_PAL` as an option to the
:command:`docker run` command. When using the Linux PAL, it is not necessary to
sign the image via a :command:`gsc sign-image` command.

.. envvar:: GSC_PAL

   Specifies the pal loader

.. code-block:: sh

   docker run ... --env GSC_PAL=Linux gsc-<image-name> ...

Example
=======

The :file:`test` folder in :file:`Tools/gsc` describes how to graphenize Docker
images and test them with sample inputs. The samples include Ubuntu-based Docker
images of Bash, Python, nodejs, Numpy, and Pytorch.

.. warning::
   All test images rely on insecure arguments to be able to set test-specific
   arguments to each application. These images are not intended for production
   environments.

The example below shows how to graphenize the public Docker image of Python3.
This example assumes that all prerequisites are installed and configured.

#. Pull public Python image from Dockerhub:

   .. code-block:: sh

      docker pull python

#. Create a configuration file:

   .. code-block:: sh

      cd Tools/gsc
      cp config.yaml.template config.yaml
      # Adopt config.yaml to the installed Intel SGX driver and desired Graphene
      # repository.

#. Graphenize the Python image using :command:`gsc build`:

   .. code-block:: sh

      ./gsc build --insecure-args python test/ubuntu18.04-python3.manifest

#. Sign the graphenized Docker image using :command:`gsc sign-image`:

   .. code-block:: sh

      # Generate signing key (if you don't already have a key)
      openssl genrsa -3 -out enclave-key.pem 3072
      # Sign graphenized Docker image with the key
      ./gsc sign-image python enclave-key.pem

#. Test the graphenized Docker image:

   .. code-block:: sh

      docker run --device=/dev/gsgx --device=/dev/*sgx \
         -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
         gsc-python -c 'print("HelloWorld!")'

Limitations
===========

This document focuses on the most important limitations of GSC.
`Issue #1520 <https://github.com/oscarlab/graphene/issues/1520>`__ provides the
complete list of known limitations and serves as a discussion board for
workarounds.

Dependency on Ubuntu 18.04
--------------------------

Docker images not based on Ubuntu 18.04 may not be compatible with GSC. GSC
relies on Graphene to execute Linux applications inside Intel SGX enclaves and
the installation of prerequisites depends on package manager and package
repositories.

GSC can simply be extended to support other distributions by providing a
template for this distribution in :file:`Tools/gsc/templates`.

Trusted data in Docker volumes
------------------------------

Data mounted as Docker volumes at runtime is not included in the general search
for trusted files during the image build. As a result, Graphene denies access to
these files, since they are neither allowed nor trusted files. This will likely
break applications using files stored in Docker volumes.

Workaround
^^^^^^^^^^

   Trusted files can be added to image-specific manifest file (first argument to
   :command:`gsc build` command) at build time. This workaround does not allow
   these files to change between build and run, or over multiple runs. This only
   provides integrity for files and not confidentiality.

Allowing dynamic file contents via Graphene protected files
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   Docker volumes can include Graphene protected files. As a result Graphene can
   open these protected files without knowing the exact contents as long as the
   protected file was configured in the manifest. The complete and secure use of
   protected files may require additional steps.

Integration of Docker Secrets
-----------------------------

Docker Secrets are automatically pulled by Docker and the results are stored
either in environment variables or mounted as files. GSC is currently unaware of
such files and hence, cannot mark them trusted. Similar to trusted data, these
files may be added to the manifest.

Access to files in excluded paths
---------------------------------

The manifest generation excludes all files and paths starting with
:file:`/boot`, :file:`/dev`, :file:`/proc`, :file:`/var`, :file:`/sys`, and
:file:`/etc/rc` from the list of trusted files. If your application
relies on some files in these directories, you must manually add them to the
manifest::

   sgx.trusted_files.[identifier] = "[URI]"
   or
   sgx.allowed_files.[identifier] = "[URI]"

Docker images with non-executables as entrypoint
------------------------------------------------

Docker images may contain a script entrypoint which is not an ELF executable.
:program:`gsc` fails to recognize such entrypoints and fails during the image
build. A workaround relies on creating an image from the application image which
has an entrypoint of the script interpreter with the script as an argument. This
allows :program:`gsc` to start the interpreter instead of the script.
