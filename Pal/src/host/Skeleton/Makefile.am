# Add host-specific compilation rules here

CC	= gcc
AS	= gcc
AR	= ar rcs

CFLAGS  = -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE -fno-builtin
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp
LDFLAGS	= -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map
ARFLAGS =

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

pal_loader = $(HOST_DIR)/libpal.so
pal_sec = $(SEC_DIR)/libpal_sec.so
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = $(HOST_DIR)/pal.map
pal_lib_post =
pal_static = $(HOST_DIR)/libpal.a
pal_gdb =
