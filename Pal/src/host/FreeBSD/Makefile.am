# Add host-specific compilation rules here
HOST_DIR = host/$(OS)

pal_lib_deps = $(HOST_DIR)/pal.map $(HOST_DIR)/pal.lds

LDFLAGS += --version-script $(HOST_DIR)/pal.map -T $(HOST_DIR)/pal.lds
