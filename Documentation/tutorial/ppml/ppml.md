## PPML Tutorial

### Remote Attestation, RA-TLS and Secret Provisioning

A very important aspect of any SGX workload is attestation. How can a remote user verify that her
application actually *runs in a correct up-to-date SGX enclave*, and that the code that runs inside
the enclave is the *actual user application*? Moreover, how can the remote user provision any secret
inputs to the application remotely and in a secure fashion and get the results of execution (also in
a secure fashion) back?

Intel SGX provides a way for the SGX enclave to attest itself to the remote user. This way the user
gains trust in the SGX enclave running in an untrusted environment, ship the application code and
data, and be sure that the *correct* application was executed inside a *genuine* SGX enclave. This
process of gaining trust in a remote SGX machine is called *remote attestation*.

Graphene contains two libraries that transparently add Remote Attestation to the application:

1. *The RA-TLS library* augments normal SSL/TLS sessions with an SGX-specific handshake callback.

2. *The Secret Provisioning library* establishes a secure SSL/TLS session between the SGX enclave
   and the remote user so that the user may gain trust in the remote enclave and provision secrets
   to it. The Secret Provisioning library builds on top of RA-TLS and typically runs before the
   application.

The Secret Provisioning library provides two simple APIs to applications: it either transparently
initializes the environment variable `SECRET_PROVISION_SECRET_STRING` with a secret obtained from
the remote user or provides C function APIs to receive secrets at any point during runtime.

Typical secrets that the user provisions to the remote SGX enclave include:

* Encryption keys (to encrypt/decrypt files, network connections, etc.);
* User credentials (usernames, passwords, tokens);
* Command-line arguments and environment variables;
* Configuration options.

For most applications, it is sufficient to preload the Secret Provisioning library (which will
automatically perform remote attestation with remote user and obtain the secret) and query the
`SECRET_PROVISION_SECRET_STRING` environment variable.

For more information on remote attestation, RA-TLS and Secret Provisioning, refer to
[this page](attestation.md).

Let's build the secret provisioning library and the secret provisioning server.

In this tutorial, we assume the DCAP-enabled platform (not the legacy EPID-based platform).


```
cd Examples/ra-tls-secret-prov/
```

You first need to build the required library for DCAP.

```
make -C ../../Pal/src/host/Linux-SGX/tools/ra-tls dcap
```

This will create `libsecret_prov_verify_dcap.so`.

Now, build the binaries and copy the required libraries.

```
make dcap pf_crypt
```

This builds several binaries including `secret_prov_server_dcap`, which is a secret provisioning server.
We will use this server to provision the secret master key to encrypt/decrypt protected input and output files used by PyTorch.

See [Secret Provisioning Minimal Examples](https://github.com/oscarlab/graphene/tree/master/Examples/ra-tls-secret-prov) for a detailed description of this example.

### Protected File System

Graphene provides [Protected File System](https://graphene.readthedocs.io/en/latest/manifest-syntax.html?highlight=protected#protected-files), which encrypts files and transparently decrypts them when the application reads or writes them.
This can be combined with Secret Provisioning such that the files are decrypted using the provisioned wrap key.

### Privacy-Preserving Machine Learning

Finally, we will transform our native PyTorch application into a privacy-preserving application.
We will encrypt all the files before we launch the enclave, and let the enclave communicate with the secret provisioning server to get attested and receive the master key for encryption and decryption of protected files.

We will start with the previous example, so copy the entire PyTorch directory.

```bash
cd Examples
cp -R pytorch ppml
cd ppml
```

First, we will encrypt all input files: `input.jpg`, `classes.txt`, and `alexnet-pretrained.pt`.
For simplicity, we will use the previously-built server in `Examples/ra-tls-secret-prov` directory.
By default, the server loads the secret key from files/wrap-key and provisions it to the PyTorch application. Therefore, we need to encrypt our files with the same key.

#### Encrypt Input Files

Move original files to a folder:
```bash
mkdir plaintext
mv input.jpg classes.txt alexnet-pretrained.pt plaintext
```

We will first copy the required files from `Examples/ra-tls-secret-prov`.

```
cp ../ra-tls-secret-prov/libsgx_util.so .
cp ../ra-tls-secret-prov/pf_crypt .
cp ../ra-tls-secret-prov/files/wrap-key .
```

Now encrypt our files with the wrap key stored in `wrap-key`, using the `pf_crypt` utility provided by Graphene.

```
LD_LIBRARY_PATH=. ./pf_crypt encrypt -w ./wrap-key -i ./plaintext/input.jpg -o input.jpg
LD_LIBRARY_PATH=. ./pf_crypt encrypt -w ./wrap-key -i ./plaintext/classes.txt -o classes.txt
LD_LIBRARY_PATH=. ./pf_crypt encrypt -w ./wrap-key -i ./plaintext/alexnet-pretrained.pt -o alexnet-pretrained.pt
```

#### Prepare Secret Provisioning
Copy the secret provisioning attest library from `Examples/ra-tls-secret-prov` to the current directory.
This library provides the logic to attest the SGX enclave, Graphene instance, and the application
running in it to the remote secret-provisioning server.


```bash
cp ../ra-tls-secret-prov/libsecret_prov_attest.so ./
```

Also, copy the certificates so that Graphene can verify the provisioning server.
These certificates are dummy mbedTLS-provided certificates; in production, you would want to generate real certificates for your secret-provisioning server and use them.
```bash
cp -R ../ra-tls-secret-prov/certs ./
```

Lastly, install the dependent libraries.

```bash
sudo apt-get install libnss-mdns libnss-myhostname
```

#### Change Manifest File

Next, we'll change the manifest file.
Open `pytorch.manifest.template` with your favorite text editor.

Replace `trusted_files` with `protected_files` for the input files.

```text
# replace this line with the following line
# sgx.trusted_files.model = file:alexnet-pretrained.pt
sgx.protected_files.model = file:alexnet-pretrained.pt
```

```text
# replace this line with the following line
# sgx.trusted_files.image = file:input.jpg
sgx.protected_files.image = file:input.jpg
```
```text
# replace this line with the following line
# sgx.trusted_files.classes = file:classes.txt
sgx.protected_files.classes = file:classes.txt
```

Also add `result.txt` as a protected file so that the application can write the encrypted result into it.

```text
sgx.protected_files.result = file:result.txt
```

Now, let's add the secret provisioning library to the manifest.

Append current directory `./` to `LD_LIBRARY_PATH`.
```text
# search for LD_LIBRARY_PATH and add ":./" at the end of the line
# this instructs in-Graphene dynamic loader to search for dependencies in the current directory
loader.env.LD_LIBRARY_PATH = /lib:/usr/lib:$(ARCH_LIBDIR):/usr/$(ARCH_LIBDIR):./
```

Add the following lines to enable remote secret provisioning and allow protected files to be transparently decrypted by the provisioned key.
```text
loader.env.LD_PRELOAD = libsecret_prov_attest.so
loader.env.SECRET_PROVISION_CONSTRUCTOR = 1
loader.env.SECRET_PROVISION_SET_PF_KEY = 1
loader.env.SECRET_PROVISION_CA_CHAIN_PATH = "certs/test-ca-sha256.crt"
loader.env.SECRET_PROVISION_SERVERS = "localhost:4433"

sgx.trusted_files.libsecretprovattest = file:libsecret_prov_attest.so
sgx.trusted_files.cachain = file:certs/test-ca-sha256.crt
sgx.remote_attestation = 1
```

Add the following lines for additional dynamic libraries used for secret provisioning.
```text
sgx.trusted_files.libnssdns = file:$(GRAPHENEDIR)/Runtime/libnss_dns.so.2
sgx.trusted_files.libnssmyhostname = file:$(ARCH_LIBDIR)/libnss_myhostname.so.2
sgx.trusted_files.libnssmdns = file:$(ARCH_LIBDIR)/libnss_mdns4_minimal.so.2
```

The following files should be also allowed for DNS hostname resolution.
Note that `sgx.allowed_files` should not be used in production.
In practice, you will need to have the expected values for these files, and use `sgx.trusted_files`.

```text
sgx.allowed_files.hostconf = file:/etc/host.conf
sgx.allowed_files.hosts = file:/etc/hosts
sgx.allowed_files.gaiconf = file:/etc/gai.conf
sgx.allowed_files.resolv = file:/etc/resolv.conf
```

Re-generate the manifest files, tokens, and signatures:

```bash
make clean
make SGX=1
```

Now, you are ready to run your privacy-preserving PyTorch example!

#### Run Privacy-Preserving Inference

We will launch the provisioning server.

In this tutorial, we will just run it locally (`localhost:4433` as configured in the manifest) for simplicity.
As previously mentioned, we will use the reference server from `Examples/ra-tls-secret-prov`.

Ideally, the user must run it on a trusted remote machine.
In that case, `loader.env.SECRET_PROVISION_SERVERS` in the manifest must point to the address of the machine.

```
cd ../ra-tls-secret-prov
./secret_prov_server_dcap &
cd -
```

Finally, let's run the application.
You don't need to change anything in the python script.
Actually, you can run it with exactly the same command you ran in the previous section.

```
SGX=1 ./pal_loader pytorch.manifest pytorchexample.py
```

#### Decrypt the Output File

After our protected PyTorch inference is finished, you'll see `result.txt` in the directory.
This file is encrypted with the same key as was used for decryption of input files.
In order to decrypt it, use the following command:

```bash
LD_LIBRARY_PATH=../ra-tls-secret-prov ../ra-tls-secret-prov/pf_crypt decrypt -w ../ra-tls-secret-prov/files/wrap-key -i ./result.txt -o plaintext/result.txt
```

You can check the result written in `./plaintext/result.txt`!

#### Cleaning Up

If you're done, kill the provisioning server

```bash
kill %%
```
