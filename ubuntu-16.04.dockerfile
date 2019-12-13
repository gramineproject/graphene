FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y build-essential autoconf gawk git bison libprotobuf-c-dev protobuf-c-compiler python3-pytest wget python3-pip cmake

RUN pip3 install protobuf

RUN git clone https://github.com/intel/linux-sgx-driver.git

RUN git clone https://github.com/oscarlab/graphene.git
RUN cd /graphene && git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
RUN openssl genrsa -3 -out /graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

RUN cd /graphene/Pal/src/host/Linux-SGX/sgx-driver && ISGX_DRIVER_PATH=/linux-sgx-driver ISGX_DRIVER_VERSION=2.4 ./link-intel-driver.py

RUN cd /graphene && make && SGX=1 make
