GLIBC_SRC = glibc-2.17
SHIM_DIR = shim
BUILD_DIR = build
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/,libc.so.6 ld-linux-x86-64.so.2)

all: $(GLIBC_TARGET)
	make -C $(SHIM_DIR) all

debug: DEBUG=debug
debug: $(GLIBC_TARGET)
	make -C $(SHIM_DIR) debug

# nothing to install
install:

$(GLIBC_TARGET): $(BUILD_DIR)/Makefile
	cd $(BUILD_DIR) && make

$(BUILD_DIR)/Makefile: $(GLIBC_SRC)/configure
	./buildglibc.py --quiet $(DEBUG)

$(GLIBC_SRC)/configure:
	[ -f $(GLIBC_SRC).tar.gz ] || \
	wget http://ftp.gnu.org/gnu/glibc/$(GLIBC_SRC).tar.gz
	tar -xzf $(GLIBC_SRC).tar.gz
	[ ! -f $(GLIBC_SRC).patch ] || git apply $(GLIBC_SRC).patch

clean:
	make -C $(SHIM_DIR) clean
	rm -rf $(BUILD_DIR)
