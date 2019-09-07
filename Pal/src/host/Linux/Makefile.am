# Add host-specific compilation rules here
SEC_DIR = security/$(PAL_HOST)

CFLAGS += -fPIC -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin -Wtrampolines

CFLAGS += -Wextra $(call cc-option,-Wnull-dereference)

ASFLAGS += -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp
LDFLAGS += -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds \
	  -z relro -z now

pal_loader = $(HOST_DIR)/libpal.so
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = pal-symbols $(HOST_DIR)/pal.map.template $(HOST_DIR)/pal.lds
pal_lib_post =
pal_static = $(HOST_DIR)/libpal.a
pal_gdb =
