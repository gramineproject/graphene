Graphene Secure Container
=========================

Docker containers are widely used to deploy applications in the cloud. Using
Graphene Secure Containers (GSC) we provide the infrastructure to deploy Docker
containers protected by Intel SGX enclaves using the Graphene Library OS.
Therefore, the :program:`gsc` tool transforms existing Docker images into a new
image (called ``gsc-<image-name>``) which includes the Graphene Library OS,
generates a manifest file and generates Intel SGX related information.

The :program:`gsc` command line tool follows the common Docker approach to first
build an image and subsequently run a container of an image. It provides the
:command:`build` command and allows to subsequently use :command:`docker run`.

The `test directory <test/README.rst>`__ provides sample Docker images and
scripts to graphenize them using :program:`gsc`.

See `gsc documentation <../../Documentation/manpages/gsc.rst>`__ for detailed
description of the command. The remainder of this document describes the
implementation.

Building graphenized Docker images
----------------------------------

The build process of a graphenized Docker image from image ``<image-name>``
follows two main stages and produces an image named ``gsc-<image-name>``.

**Graphene build:** The first stage compiles Graphene based on the provided
configuration (see :file:`config.json`) which includes the
distribution (e.g., Ubuntu18.04) and the Intel SGX driver details.

**Graphenizing the base image:** The second stage copies the important Graphene
artifacts (e.g., the runtime and signer tool) from the first stage. It then
prepares image-specific variables such as the executable path and the library
path, and scanning the entire image to generate a list of trusted files. GSC
excludes files from ``/boot``, ``/dev``, ``/proc``, ``/var``, ``/sys`` and
``/etc/rc`` folders, since checksums are required which either don't exist or
may vary across different deployment machines. GSC combines these values and
list of trusted files to a new manifest file. Graphene's signer tool generates a
SIGSTRUCT file for SGX enclave initialization. This tool also generates an
SGX-specific manifest file. In a last step the entrypoint is changed to launch
the ``apploader.sh`` script which generates an Intel SGX token and starts the
``pal-Linux-SGX`` loader.

Running graphenized Docker images
---------------------------------

Docker images (named ``<image-name>``) are run inside containers via a run
command (i.e., ``docker run <image-name>``). In case of GSC, the graphenized
image is run via the regular Docker command line interface. It requires to add
``isgx`` and ``gsgx`` as devices and mount the AESMD socket file as a volume.

Limitations
-----------

Dependency on Ubuntu 16.04/18.04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Docker images not based on Ubuntu 16.04 or 18.04 may not be compatible with GSC.
GSC relies on Graphene to execute Linux applications inside Intel SGX enclaves.
These applications have library dependencies which must match Graphene's
standard libraries such as libc. Otherwise, system calls are emulated using
Linux signals causing Intel SGX exits and in general runtime overhead.

Trusted data in Docker volumes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Data mounted as Docker volumes at runtime is not included in the general search
for trusted files during the image build. As a result, Graphene denies access to
these files, since they are neither allowed nor trusted files. This will likely
break applications using files stored in Docker volumes.

**Work around:** Trusted files can be added to image specific manifest file
(first argument to ``gsc build`` command) at build time. This work around does
not allow these files to change between build and run, or over multiple runs.

**Allowing dynamic file contents via Graphene protected file systems:** Once
protected file systems are supported by Graphene, Docker volumes could include
protected file systems. As a result Graphene can open these protected file
systems without knowing the exact contents.

Integration of Docker Secrets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Docker Secrets are automatically pulled by Docker and the results are stored
either in environment variables or mounted as files. GSC is currently unaware of
such files and hence, cannot mark them trusted. Similar to trusted data, these
files may be added to the image specific manifest file.

Access to files in excluded folders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The manifest generation excludes all files in ``/boot``, ``/dev``, ``/proc``,
``/var``, ``/sys``, and ``/etc/rc`` directories from the list of trusted files.
If your application relies on some files in these directories, you must manually
add them to the application-specific manifest::

    sgx.trusted_file.specialFile=file:PATH_TO_FILE
    or
    sgx.allowed_file.specialFile=file:PATH_TO_FILE
