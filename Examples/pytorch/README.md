# PyTorch

This directory contains steps and artifacts to run a PyTorch sample workload on
Graphene. Specifically, this example uses a pre-trained model for image
classification.

The workload reads an image from a file on disk `input.jpg` and runs the
classifier to detect what object is present in the image. For the image shipping
with the workload, the output should be

```
[('Labrador retriever', 41.58518600463867), ('golden retriever', 16.59165382385254), ('Saluki, gazelle hound', 16.286855697631836), ('whippet', 2.853914976119995), ('Ibizan hound, Ibizan Podenco', 2.3924756050109863)]
```

With high probability (41%) the classifier detected the image to contain a
Labrador retriever.

# Pre-requisites

The following steps should suffice to run the workload on a stock Ubuntu 18.04
installation.

- `sudo apt install libnss-mdns libnss-myhostname` to install additional
  DNS-resolver libraries.
- `sudo apt install python3-pip lsb-release` to install `pip` and `lsb_release`.
  The former is required to install additional Python packages while the latter
is used by the Makefile.
- `pip3 install --user torchvision pillow` to install the torchvision and pillow
  Python packages and their dependencies (usually in $HOME/.local). WARNING:
This downloads several hundred megabytes of data!
- `python3 download-pretrained-model.py` to download and save the pre-trained
  model.  WARNING: this downloads about 200MB of data!

# Build

Run `make` to build the non-SGX version and `make SGX=1` to build the SGX
version.

## Building with a local Python installation

By default, the `make` command creates the manifest for the Python binary from
the system installation. If you have a local installation, you may create the
manifest with the `PYTHONPATH` variable set accordingly. You can also specify a
particular version of Python. For example:

```
make PYTHONPATH=<python install path> PYTHONVERSION=python3.6 SGX=1
```

# Run

Execute any one of the following commands to run the workload:

- natively: `python3 pytorchexample.py`
- Graphene w/o SGX: `graphene-direct ./pytorch ./pytorchexample.py`
- Graphene with SGX: `graphene-sgx ./pytorch ./pytorchexample.py`
