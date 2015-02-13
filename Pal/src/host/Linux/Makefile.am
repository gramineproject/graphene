# Add host-specific compilation rules here
HOST_DIR = host/$(OS)
SEC_DIR = security/$(OS)

pal_sec = $(SEC_DIR)/libpal_sec.so
pal_lib_deps = $(HOST_DIR)/pal.map $(HOST_DIR)/pal.lds

LDFLAGS += --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds
