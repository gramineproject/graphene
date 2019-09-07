# Add host-specific compilation rules here

CFLAGS += -fPIC -U_FORTIFY_SOURCE \
         -fno-stack-protector -fno-builtin

CFLAGS += -Wextra -Wno-unused-parameter -Wno-sign-compare $(call cc-option,-Wnull-dereference)

ASFLAGS += -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp
LDFLAGS += -shared -nostdlib -z combreloc -z defs \
	  --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds

pal_loader =
pal_sec =
pal_lib = $(HOST_DIR)/libpal.so
pal_lib_deps = pal-symbols $(HOST_DIR)/pal.map.template $(HOST_DIR)/pal.lds
pal_lib_post =
pal_static =
pal_gdb =
