SYS ?= $(shell gcc -dumpmachine)
export SYS

export DEBUG

GLIBC_SRC = glibc-2.19
SHIM_DIR = shim
BUILD_DIR = glibc-build
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/,libc.so.6 ld-linux-x86-64.so.2 libpthread.so.0 libm.so.6 libdl.so.2 libutil.so.1 crt1.o crti.o crtn.o liblibos.so.1 libnss_dns.so.2 libresolv.so.2)

.PHONY: all
all: $(GLIBC_TARGET)
	$(MAKE) -C $(SHIM_DIR) all

ifeq ($(SYS),x86_64-linux-gnu)

.INTERMEDIATE: $(BUILD_DIR)/Build.success

$(BUILD_DIR)/Build.success: $(BUILD_DIR)/Makefile
	@echo "Building glibc, may take a while to finish. Warning messages may show up. If this process terminates with failures, see \"$(BUILD_DIR)/build.log\" for more information."
	cd $(BUILD_DIR) && ($(MAKE) 2>&1 >> build.log)
#  2>&1 | tee -a build.log)

$(GLIBC_TARGET): $(BUILD_DIR)/Build.success

$(BUILD_DIR)/Makefile: $(addprefix $(GLIBC_SRC)/,configure elf/Versions nptl/Versions dlfcn/Versions)
ifeq ($(DEBUG),1)
	./buildglibc.py --quiet --debug
else
	./buildglibc.py --quiet
endif

ifeq ($(shell git ls-files $(GLIBC_SRC)/configure),)
$(GLIBC_SRC)/configure: $(GLIBC_SRC).patch
	[ -f $(GLIBC_SRC).tar.gz ] || \
	wget http://ftp.gnu.org/gnu/glibc/$(GLIBC_SRC).tar.gz
	tar -xzf $(GLIBC_SRC).tar.gz
	cd $(GLIBC_SRC) && patch -p1 < ../$(GLIBC_SRC).patch
	cd $(GLIBC_SRC) && patch -p1 < ../glibc-fix-warning.patch
endif

.PHONY: clean
clean:
	$(MAKE) -C $(SHIM_DIR) clean
	rm -rf $(BUILD_DIR)

else
.IGNORE: $(GLIBC_TARGET)
$(GLIBC_TARGET):

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
endif
