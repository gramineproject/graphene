## Prerequisites
- **PyTorch (Python3)**
	- PyTorch is a framework for machine learning based on Python. Please [install PyTorch](https://pytorch.org/get-started/locally/) before you proceed. We will use Python3 in this tutorial.
- **Intel SGX SDK & Platform Software**
	- You need a machine that supports Intel SGX. Please follow [this guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Installation_Guide_Linux_2.10_Open_Source.pdf) to install Intel SGX SDK and Platform Software. Make sure to install the driver with ECDSA attestation enabled.
- **Graphene**
	- Graphene can host unmodified binaries inside Intel SGX enclaves. Follow [Quick Start](https://graphene.readthedocs.io/en/latest/quickstart.html) to build Graphene.
