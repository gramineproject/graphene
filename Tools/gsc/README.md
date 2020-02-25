# Graphene Secure Container

Docker containers are widely used to deploy applications in the cloud. Using Grpahene Secure
Containers (GSC) we provide the infrastructure to deploy Docker containers protected by Intel SGX
enclaves using the Graphene Library OS. Therefore, the `gsc` tool transforms existing Docker images
into a new image (called `gsc-<image-name>`) which includes the Graphene Library OS, generate a
manifest file and generate Intel SGX related information.

The `gsc` command line tool follows the common Docker approach to first build an image and
subsequently run a container of an image. It provides the `build` command and allows to subsequently
use `docker run`.

The [test directory](test/README.md) provides sample Docker images and scripts to graphenize them
using `gsc`.

## Prerequisites to running GSC

**Software packages:**

```
sudo apt install docker.io python3
pip3 install docker
```

**Kernel modules and serivces:**
- Follow installation instructions for [Intel SGX driver](https://github.com/intel/linux-sgx-driver)
- Follow installation instructions for [Intel SGX
  SDK](https://01.org/intel-software-guard-extensions/downloads)
- Follow the installation instructions for [Graphene](https://github.com/oscarlab/graphene) 

**Configurations:**
- User must have access to Docker daemon

```
sudo adduser $USER docker
```

## Building graphenized Docker images

The build process of a graphenized Docker image from image `<image-name>` follows two main stages
and produces an image named `gsc-<image-name>`.

**Graphene build:** The first stage compiles Graphene based on the provided configuration (see
[config.json](config.json)) which includes the distribution (i.e., Ubuntu18.04) and the Intel SGX
driver details. 

**Graphenizing the base image:** The second stage copies the important Graphene artifacts (e.g., the
runtime and signer tool) from the first stage. It then prepares the manifest file by adding image
specific variables such as the executable path and the library path, and scanning the entire image
to generate a list of trusted files. Based on this manifest file, we use Graphene's signer tool to
generate a signature and the Intel SGX manifest file. Afterwards we remove any previously created
files or installed packages. In a last step the entrypoint is changed to launch the `apploader.sh`
script which generates SGX token and starts the `pal-Linux-SGX` loader.

## Running graphenized docker images

Docker images (named `<image-name>`) are run inside containers via a run command (i.e., `docker run
<image-name>`). In case of GSC, the graphenized image is run via the regular Docker command line
interface. It requires to add `isgx` and `gsgx` as devices and mount the AESMD socket file as a
volume.

## Detailed Usage

```
gsc <cmd> [<cmd arguments>]
```

### List of Commands

*build* - Build a graphenized Dcker image

*help* - Print this information

### Build command 

```
gsc build <manifest> <image-name>[:<tag>] [<options>]
```

*manifest* - Application specific manifest entries 

*image-name* - Name of the base image

*tag* - Tag of the base image

**Options:**

`-d` - compile Graphene with debug flags and output

`-L` - compile Graphene with Linux PAL in addition to Linux-SGX PAL

### Run graphenized Docker images

Execute Docker run command via Docker CLI and provide gsgx and sgx device, and the PSW/AESM socket.
Additional docker options and application arguments may be supplied to the Docker run command.

```
docker run --device=/dev/gsgx --device=/dev/isgx -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [options] gsc-<image-name>[:<tag>] [application arguments]
```

*image-name* - Name of image without GSC build

*tag* - Tag of the image to be used

*application arguments* - Application arguments to be supplied to the application launching inside
the Docker container and Graphene

*options* - Options are passed through to Docker run. Common options include `-it` (interactive with
terminal) or `-d` (detached). Please see [docker
manual](https://docs.docker.com/engine/reference/commandline/run/) for details.

**Execute with Linux PAL instead of Linux-SGX PAL**:
When specifying `-L` during GSC `build`, you may select the Linux PAL at docker run time instead of
the Linux-SGX PAL. By specifying the environment variable `LINUX_PAL` as an option to the docker
`run` command.

```
docker run ... --env LINUX_PAL=linux gsc-<image-name> ...
```

### GSC Configuration parameters

GSC is configured via a configuration file called [config.json](config.json) with the following
parameters:

**sgxdriver_repository**: From which repository should the driver be checked out.

**sgxdriver_version**: Defines the SGX driver driver version to be checked out from the
`sgxdriver_repository`. Default value is master.

**distro**: Defines Linux distribution to be used to build Graphene in. Currently supports
ubuntu18.04 and ubuntu16.04.

## Limitations

### Dependence on Ubuntu 16.04/18.04

Docker images not based on Ubuntu 16.04 or 18.04 may not be compatible with GSC. GSC relies on
Graphene to execute Linux applications inside Intel SGX enclaves. These applications have library
dependency which must match Graphene's standard libraries such as libc. Otherwise, system calls are
emulated using Linux signals causing Intel SGX exits and in general runtime overhead.

### Trusted data in Docker volumes

Data mounted as Docker volumes at runtime is not included in the general search for trusted files
during the image build. As a result, Graphene denies access to these files, since they are neither
allowed or trusted files. This will likely break applications using files stored in Docker volumes.

**Work around:** Trusted files can be added to image specific manifest file (first argument to `gsc
build` command) at build time. This work around does not allow these files to change between build
and run, or over multiple runs. 

**Allowing dynamic file contents via Graphene protected file systems:** Once protected file systems
are supported by Graphene, Docker volumes could include protected file systems. As a result Graphene
can open these protected file systems without knowing the exact contents.

### Integration of Docker Secrets

Docker Secrets are automatically pulled by Docker and the results stored either in environment
variables or mounted as files. GSC is currently unaware of such files and hence, cannot mark them
trusted. Similar to trusted data these files may be added to the image specific manifest file.