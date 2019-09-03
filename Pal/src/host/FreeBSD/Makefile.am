# Add host-specific compilation rules here
HOST_DIR = host/$(PAL_HOST)

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin -Wtrampolines
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp
LDFLAGS	= -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds
ARFLAGS	=

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

pal_loader = $(HOST_DIR)/libpal.so
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = $(HOST_DIR)/pal.map $(HOST_DIR)/pal.lds
pal_lib_post =
pal_static = $(HOST_DIR)/libpal.a
