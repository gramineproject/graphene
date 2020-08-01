## PyTorch with Graphene

Now, we will run the previous example with [Graphene](https://grapheneproject.io/) open-source library OS.
Graphene allows an unmodified binary to run on different platforms, including Intel SGX enclaves.

When Graphene runs an executable, it reads a *manifest file* that describes the execution environment including the security posture, environment variables, dynamic libraries, arguments, and so on.
Graphene supports seamless porting of an application into an Intel SGX enclave based on the manifest.
For SGX enclaves, the manifest should also include the hashes of all dependent libraries and trusted files such that the adversary cannot tamper with them.
Please refer to [this](https://graphene.readthedocs.io/en/latest/manifest-syntax.html) for further details about the syntax of Graphene manifests.

Before you start, please see [Prerequisites](prerequisites.md) and make sure you have built both of the Graphene loaders (`Runtime/pal-Linux` and `Runtime/pal-Linux-SGX`).

### Putting PyTorch into Graphene Library OS

Now, we will run the previous example using Graphene library OS.

Navigate to the PyTorch example directory that we were in the previous section.

```bash
cd <graphene repository>/Examples/pytorch
```

Now, take a look at the template manifest file `pytorch.manifest.template`.
We will take a look at only a few entries of the file.

The executable is `python3`, which is located at the host path `/usr/bin/python3`:
```text
loader.exec = file:/usr/bin/python3
```

We will mount the entire `$(GRAPHENEDIR)/Runtime/`  directory to the `/lib` in the library OS:
```text
fs.mount.lib.type = chroot
fs.mount.lib.path = /lib
fs.mount.lib.uri = file:$(GRAPHENEDIR)/Runtime/
```

We also mount other directories such as `/usr`,  `/etc`, and `/tmp`.
Finally, we mount the path containing the python packages:

```text
fs.mount.pip.type = chroot
fs.mount.pip.path = $(HOME)/.local/lib
fs.mount.pip.uri = file:$(HOME)/.local/lib
```

For now, ignore the entries starting with `sgx`.

Now,  if you run `make`, it will perform the following:
1. Generate the actual manifest (`pytorch.manifest`) from the template
2. Create a symbolic link of the Graphene loader (`pal_loader`)

```bash
make
```

Now, launch Graphene with the generated manifest.
You can simply append the arguments after the manifest name.
Our example takes `pytorchexample.py` as an argument:

```bash
./pal_loader pytorch.manifest pytorchexample.py
```

That's it. You have run the PyTorch example with Graphene.

### Executing in an SGX Enclave

In this section, we will learn how to use Graphene to run the same PyTorch example inside an Intel SGX enclave.
Let's go back to the manifest template.

Please note that the manifest keys starting with `sgx` are SGX-specific syntax.
These entries are ignored if Graphene is not running with SGX.

Again, we will highlight some of the SGX-specific entries in `pytorch.manifest.template`.
SGX syntax is fully described in [here](https://graphene.readthedocs.io/en/latest/manifest-syntax.html?highlight=manifest#sgx-syntax).

First, you may see the following lines in the manifest template.
```text
sgx.trusted_files.ld = file:$(GRAPHENEDIR)/Runtime/ld-linux-x86-64.so.2
sgx.trusted_files.libc = file:$(GRAPHENEDIR)/Runtime/libc.so.6
...
```

`sgx.trusted_files.<name>` specifies the file that will be verified, thus trusted by the enclave.
Before we run the enclave, we generate the actual SGX manifest file
with `pal-sgx-sign` utility.
The utility will calculate the hash of each trusted file and append `sgx.trusted_checksum.<name>`.

On the other hand, `sgx.allowed_files.<name>` specifies a file that will be unconditionally allowed by the enclave.
The file will not be cryptographically hashed and verified.
Thus, this is insecure and discouraged for production use (unless you are sure that the contents of the file are irrelevant to security of your workload).

```text
sgx.allowed_files.pythonhome = file:$(HOME)/.local/lib
```

This line unconditionally allows all python libraries in the path to be loaded into the enclave.
Ideally, the developer needs to replace it with `sgx.trusted_files` for each of the dependent python libraries.
Note that our example is using `sgx.allowed_files` for simplicity.


```text
sgx.allow_file_creation = 1
```
This allows the enclave to generate new files.
We need this as the python script writes the result to `result.txt`.

So far, we saw how the manifest template looks like.
We will now prepare all the files needed to run the program in SGX enclaves.

```bash
make SGX=1
```

Above command will do the following:
1. Generate the SGX manifest file `pytorch.manifest.sgx`
1. Sign the manifest and generate the signature file (`pytorch.sig`)
2. Retrieve `aesmd` token and write it to `pytorch.token`

After the command, you can simply set `SGX=1` environment variable and use `pal_loader` to launch the application with an SGX enclave.

```bash
SGX=1 ./pal_loader pytorch.manifest.sgx pytorchexample.py
```

It will run exactly the same python script, but inside the SGX enclave!
