# Add host-specific compilation rules here
HOST_DIR = host/$(PAL_HOST)
SEC_DIR = security/$(PAL_HOST)

CFLAGS	= -Wall -fPIC -O2 -std=c11 -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin

EXTRAFLAGS = -Wextra -Wno-sign-compare $(call cc-option,-Wnull-dereference)

CFLAGS += $(EXTRAFLAGS)

ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp
LDFLAGS	= -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds
ARFLAGS	=

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

pal_loader = $(HOST_DIR)/libpal.so
pal_sec = $(SEC_DIR)/libpal_sec.so
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = pal-symbols $(HOST_DIR)/pal.map.template $(HOST_DIR)/pal.lds
pal_lib_post =
pal_static = $(HOST_DIR)/libpal.a
pal_gdb =
