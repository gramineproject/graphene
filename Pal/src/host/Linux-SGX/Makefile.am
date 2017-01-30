# Add host-specific compilation rules here
HOST_DIR = host/$(OS)

CC	= gcc
AS	= gcc
AR	= ar rcs
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -maes -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin -DIN_ENCLAVE
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp -DIN_ENCLAVE
LDFLAGS	= -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T host/$(OS)/enclave.lds \
	  --hash-style=gnu -e enclave_entry
ARFLAGS	=

pal_loader = host/$(OS)/pal-sgx
pal_sec =
pal_lib = libpal-enclave.so
pal_lib_deps = host/$(OS)/enclave.lds host/$(OS)/pal.map
pal_lib_post = libpal.so
pal_static = libpal.a
