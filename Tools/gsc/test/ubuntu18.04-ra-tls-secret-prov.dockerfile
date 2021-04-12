FROM ubuntu:18.04

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y wget \
    build-essential \
    python3 \
    libcurl3-gnutls \
    gnupg2

# Installing DCAP and EPID-specific libraries

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \
    > /etc/apt/sources.list.d/intel-sgx.list \
    && wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    && apt-key add intel-sgx-deb.key

RUN apt-get update \
    && apt-get install -y libsgx-urts \
    libsgx-dcap-ql \
    libsgx-epid

# Build environment of this Dockerfile should point to the root of Graphene directory

RUN mkdir -p /graphene/Scripts \
    && mkdir -p /graphene/Pal/src/host/Linux-SGX/tools/pf_crypt \
    && mkdir -p /graphene/Pal/src/host/Linux-SGX/tools/common \
    && mkdir -p /graphene/Pal/src/host/Linux-SGX/tools/ra-tls \
    && mkdir -p /graphene/Examples/ra-tls-secret-prov

# The below files are copied to satisfy Makefile dependencies of graphene/Examples/ra-tls-secret-prov

COPY Scripts/Makefile.configs  /graphene/Scripts/
COPY Scripts/Makefile.Host  /graphene/Scripts/
COPY Scripts/download  /graphene/Scripts/

COPY Pal/src/host/Linux-SGX/tools/pf_crypt/pf_crypt /graphene/Pal/src/host/Linux-SGX/tools/pf_crypt/
COPY Pal/src/host/Linux-SGX/tools/common/libsgx_util.so /graphene/Pal/src/host/Linux-SGX/tools/common/

# make sure RA-TLS DCAP libraries are built in host Graphene via:
# cd graphene/Pal/src/host/Linux-SGX/tools/ra-tls && make dcap

COPY Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_attest.so /graphene/Pal/src/host/Linux-SGX/tools/ra-tls/
COPY Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_verify_dcap.so /graphene/Pal/src/host/Linux-SGX/tools/ra-tls/
COPY Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_verify_epid.so /graphene/Pal/src/host/Linux-SGX/tools/ra-tls/
COPY Pal/src/host/Linux-SGX/tools/ra-tls/secret_prov.h /graphene/Pal/src/host/Linux-SGX/tools/ra-tls/

# If user doesn't want to copy above files, then she can build the ra-tls-secret-prov sample locally
# and copy the entire directory with executables

COPY Examples/ra-tls-secret-prov /graphene/Examples/ra-tls-secret-prov

WORKDIR /graphene/Examples/ra-tls-secret-prov

RUN make clean \
    && make clients epid dcap files/input.txt

ENV LD_LIBRARY_PATH = "${LD_LIBRARY_PATH}:./libs"

ENV PATH = "${PATH}:/graphene/Examples/ra-tls-secret-prov"

ENTRYPOINT ["/graphene/Examples/ra-tls-secret-prov/secret_prov_client"]
