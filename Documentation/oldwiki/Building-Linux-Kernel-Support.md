# Building Linux Kernel Support
Graphene requires modifications to the Linux kernel for faster memory copy across processes and security isolation. To enable the security isolation, it requires the whole Linux kernel to be recompiled and installed into the host. The fast memory bulk copy feature can be built into a standalone Linux kernel module, or built as a part of a Graphene kernel.

## Building Graphene Kernel

To build a Graphene kernel, simply use the following commands under the Graphene source tree:
    cd PAL
    make  (This step will download and patch Linux 3.19 kernel source, and fail when no .config file provided)
    cd linux-3.19
    make menuconfig
    make
    make headers_install
    make modules_install
    make install    

During configuring the kernel, there are certain Graphene-specific options that need to be enabled:

* `CONFIG_GRAPHENE`:
  Enabling Graphene support. This option is REQUIRED.

* `CONFIG_GRAPHENE_ISOLATE`:
  Enabling Graphene security isolation (sandboxing) feature. If this option is disabled, a Graphene instance is still isolated from other processes, but sandboxing inside a Graphene instance is not possible.

* `CONFIG_GRAPHENE_BULK_IPC`:
  Enabling Graphene fast memory bulk copy feature, as part of the Graphene kernel.

* `CONFIG_GRAPHENE_DEBUG`:
  Printing Graphene debug log to the kernel log.

After `make install`, you may want to update the GRUB boot menu with a new entry. The following command can be used to update the GRUB menu in most Linux host:

    update-grub

If you are building the kernel in a Ubuntu host, we suggest you to use `make-kpkg` to build the kernel into a _.deb_ package and install it. By doing so, you can conveniently install and remove the kernel by `apt-get` and `dpkg`. 

## Building Graphene Fast Memory Bulk Copy Module

If you don't want to run Graphene with reference monitor, you may build the fast memory bulk copy into a standalone Linux kernel module and install it into the current kernel. To build and install the module, run the following commands under the Graphene source tree:

    cd Pal/ipc/linux
    make
    sudo ./load.sh
