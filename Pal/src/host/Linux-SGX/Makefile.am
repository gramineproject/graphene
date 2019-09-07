# Add host-specific compilation rules here

CFLAGS += -fPIC -maes -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin -Wtrampolines

CFLAGS += -Wextra $(call cc-option,-Wnull-dereference)

ASFLAGS += -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp
LDFLAGS += -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/enclave.lds \
	  --hash-style=gnu -z relro -z now

CRYPTO_PROVIDER = mbedtls
CFLAGS += -DCRYPTO_USE_MBEDTLS

pal_loader = $(HOST_DIR)/pal-sgx
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = pal-symbols $(HOST_DIR)/pal.map.template $(HOST_DIR)/enclave.lds
pal_static = $(HOST_DIR)/libpal.a
pal_gdb = $(HOST_DIR)/debugger/gdb
pal_signer = pal-sgx-get-token pal-sgx-sign aesm_pb2.py
