FROM ubuntu:18.04 AS graphene

# Add steps here to set up dependencies
RUN env DEBIAN_FRONTEND=noninteractive apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        autoconf \
        bison \
        build-essential \
        coreutils \
        gawk \
        git \
        libcurl4-openssl-dev \
        libprotobuf-c-dev \
        protobuf-c-compiler \
        python3-protobuf \
        wget

# Clone Graphene
RUN git clone https://github.com/oscarlab/graphene.git /graphene

# Init submodules
RUN cd /graphene \
    && git fetch origin master \
    && git checkout master

# Create SGX driver for header files
RUN cd /graphene/Pal/src/host/Linux-SGX \
    && git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git linux-sgx-driver \
    && cd linux-sgx-driver \
    && git checkout DCAP_1.7 && cp -r driver/linux/* .

# Build Graphene-SGX
RUN cd /graphene && ISGX_DRIVER_PATH=/graphene/Pal/src/host/Linux-SGX/linux-sgx-driver \
    make -s -j4 SGX=1 WERROR=1 \
    && true

# Translate runtime symlinks to files
RUN for f in $(find /graphene/Runtime -type l); do cp --remove-destination $(realpath $f) $f; done
