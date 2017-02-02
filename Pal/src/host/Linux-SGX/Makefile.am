# Add host-specific compilation rules here
HOST_DIR = host/$(PAL_HOST)

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
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/enclave.lds \
	  --hash-style=gnu -e enclave_entry
ARFLAGS	=

pal_loader = $(HOST_DIR)/pal-sgx
pal_sec =
pal_lib = libpal-enclave.so
pal_lib_deps = $(HOST_DIR)/enclave.lds $(HOST_DIR)/pal.map
pal_lib_post = libpal.so
pal_static = libpal.a
pal_gdb = $(HOST_DIR)/debugger/gdb
