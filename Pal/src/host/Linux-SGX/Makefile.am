# Add host-specific compilation rules here

SGX_SDK ?= /opt/intel/sgxsdk

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign

pal_loader = host/$(OS)/pal-sgx
pal_lib = libpal-enclave.so
pal_lib_deps = host/$(OS)/enclave.lds host/$(OS)/pal.map
pal_lib_post = libpal.so

CFLAGS += -DIN_ENCLAVE
LDFLAGS += --version-script host/$(OS)/pal.map \
	   -T host/$(OS)/enclave.lds --hash-style=gnu -e enclave_entry
