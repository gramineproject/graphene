# Graphene Secure Container

Docker containers are widely used to deploy applications in the cloud. Using Grpahene Secure Containers (GSC) we provide the infrastrucuture to deploy docker containers protected by Intel SGX enclaves using the Graphene Library OS. Therefore, the `gsc` tools transforms existing docker images into a new image (called `gsc-<image name>`) which includes the Graphene Library OS, generate a manifest file and generate Intel SGX related information.

The `gsc` command line tool follows the common docker approach to first build an image and subsequently run a container of an image. It provides two commands `build` and `run`.

**Sample Images**:
The test [folder](test/README.md) provides sample docker images and scripts to graphenize them using `gsc`. The list of examples includes:

* Hello-World
* Python3

## Prerequisits to running GSC

**Software packages:**
- docker.io
- python3

```
apt install docker.io python3
```

**Kernel modules and serives:**
- Follow installation instructions for [Intel SGX driver](https://github.com/intel/linux-sgx-driver)
- Follow installation instructions for [Intel SGX SDK](https://01.org/intel-software-guard-extensions/downloads)
- Follow the installation instructions for [Graphene](https://github.com/oscarlab/graphene) or only install the Graphene kernel module as described below:

```
# Download Graphene
git clone https://github.com/oscarlab/graphene.git
cd graphene 
git submodule init
git submodule update
cd Pal/src/host/Linux-SGX/sgx-driver

# Get Intel SGX driver and configure kernel module for driver version
git clone https://github.com/01org/linux-sgx-driver.git && cd linux-sgx-driver && git checkout sgx_driver_${sgxdriver_major}.${sgxdriver_minor} && cd -
echo "#include <linux/version.h>" > isgx_version.h
echo "#define SDK_DRIVER_VERSION KERNEL_VERSION(${sgxdriver_major}, ${sgxdriver_minor}, 0)" >> isgx_version.h
echo "#define SDK_DRIVER_VERSION_STRIN5 ${sgxdriver_major}.${sgxdriver_minor}" >> isgx_version.h

# Compile kernel module
make

# Load isgx and gsgx kernel module
sudo ./load.sh
```

**Configurtions:**
- User must have access to docker deamon 

```
sudo adduser $USER docker
```

- Setting vm.mmap_min_addr to 0

```
sudo sysctl vm.mmap_min_addr=0
```

## Building graphenized docker images

The build process of a graphenized docker image from image `<image-name>` follows two main stages and produces an image named `gsc-<image name>`.

**Graphene build:** The first stage compiles Graphene based on the provided configuration (see [config.json](config.json)) which includes the version of Ubuntu and the Intel SGX driver version. 

**Graphenizing the base image:** The second stage copies the important Graphene artifacts (e.g., the runtime and signer tool) from the first stage. It then prepares the manifest file by adding image specific variables such as the executable path and the library path, and scanning the entire image to generate a list of trusted files. Based on this manifest file, we use Graphene's signer tool to generate a signature and the Intel SGX manifest file. Afterwards we remove any previously created files or installed packages. In a last step the entrypoint is changed to one which launches the application using the pal-Linux-SGX loader from Graphene.

## Running graphenized docker images

Docker images (named `<image name>`) are run inside containers via a run command (i.e., `docker run <image name>`). In case of GSC, the graphenized image can either be called via the regular docker command line interface or `gsc` to provide even more handy tool that releaves its users of most translation tasks. It automatically adds `isgx` and `gsgx` as devices and mounts the AESMD socket file as a volume. Typically parameters to docker run can be specified as options. `gsc` then executes the regular docker run command.

## Usage

```
gsc <cmd> [<cmd arguments>]
```

### List of Commands

*build* - Build a graphenized docker image

*run* - Run a previously build graphenized docker image

*help* - Print this information

#### Build command 

```
gsc build <manifest> <image name>[:<tag>] [<options>]
```

*manifest* - 

*image name* - 

*tag* - 

**Options:**

-d - compile Graphene with debug flags and output

#### Run command
```
gsc run [options] <image name>[:<tag>] [application] [application arguments]
```

*image name* - Name of image without GSC build

*tag* - Tag of the image to be used

*application* - Application to be launched (in case the image is configured to launch /bin/bash)

*application arguments* - Application arguments to be supplied to the application launching inside the docker container and Graphene

Options are passed through to docker run. Common options include -it.

#### Configuration parameters

GSC is configed via a configuration file called [config.json](config.json). Currently includes the following parameter.

**sgxdriver_major**: Defines the major version (1 or 2) of the used Intel SGX driver on the host machine executing docker containers.

**sgxdriver_minor**: Defines the minor version of the used Intel SGX driver on the host machine executing docker containers.

**ubuntu**: Defines the Ubuntu version (16.04 or 18.04) installed on the host executing the docker images.

## Limitations

### Dependence on Ubuntu 16.04/18.04

Docker images which are not basd on Ubuntu 16.04 or 18.04 may not be compatibile with GSC. GSC relies on Graphene to execute Linux applications inside Intel SGX enclaves. Both Graphene and the applications have a libc dependency that has to match. Please look at the configuration options to ensure that the correct dependencies are met.

### Trusted data in docker volumes

Data mounted as docker volumes at runtime is not included in the general search for trusted files during the image build. As a result, Graphene does not check their SHA256 checksums to match the file which results in a possibility to insert untrusted files into the Graphene runtime or not beeing able to access these files.

**Work around:**
Trusted files can be added to image specific manifest file (first argument to `gsc build` command) at build time. This soltion does not allow these files to change between build and run, or over multiple runs. 

**Allowing dynamic file contents via Graphene protected file systems:**
Once protected file systems are supported by Graphene, docker volumes could include protected file systems. As a result Graphene can open these protected file systems without knowing the exact contents.

### Restricting socket access

Docker containers providing a service are provided with a specific interface. Graphenes current manifest does not allow to further restrict the Graphene runtime to only open these connections. *This feature is planned for future releases.* 

### Integration of Docker Secrets

Docker Secrets are automatically pulled by docker and the results stored either in environment variables or mounted as files. GSC is currently unaware of such files and hence, cannot mark them trusted. Similar to trusted data these files may be added to the image specific manifest file.