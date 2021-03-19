FROM ubuntu:18.04 AS graphene

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
        wget \
    && python3 -B -m pip install toml>=0.10

RUN git clone https://github.com/oscarlab/graphene.git /graphene

RUN cd /graphene \
    && git fetch origin master \
    && git checkout master

RUN cd /graphene/Pal/src/host/Linux-SGX \
    && git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git linux-sgx-driver \
    && cd linux-sgx-driver \
    && git checkout DCAP_1.7 && cp -r driver/linux/* .

RUN cd /graphene \
    && ISGX_DRIVER_PATH=/graphene/Pal/src/host/Linux-SGX/linux-sgx-driver \
    make -s -j WERROR=1 SGX=1



# Translate runtime symlinks to files
RUN for f in $(find /graphene/Runtime -type l); do cp --remove-destination $(realpath $f) $f; done
