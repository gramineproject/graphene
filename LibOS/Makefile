SYS ?= $(shell gcc -dumpmachine)
export SYS

export DEBUG

GLIBC_SRC = glibc-2.19
GLIBC_CHECKSUM = 18ad6db70724699d264add80b1f813630d0141cf3a3558b4e1a7c15f6beac796
SHIM_DIR = shim
BUILD_DIR = glibc-build
RUNTIME_DIR = $(CURDIR)/../Runtime
GLIBC_LIBS = \
	elf/ld-linux-x86-64.so.2 \
	nptl/libpthread.so.0 \
	libc.so \
	libc.so.6 \
	nptl_db/libthread_db.so.1 \
	math/libm.so.6 \
	dlfcn/libdl.so.2 \
	login/libutil.so.1 \
	csu/crt1.o \
	csu/crti.o \
	csu/crtn.o \
	rt/librt.so.1 \
	resolv/libnss_dns.so.2 \
	resolv/libresolv.so.2 \
	libos/liblibos.so.1
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/, $(GLIBC_LIBS))
GLIBC_RUNTIME = $(addprefix $(RUNTIME_DIR)/, $(notdir $(GLIBC_TARGET)))

.PHONY: all
all: $(GLIBC_TARGET) $(GLIBC_RUNTIME)
	$(MAKE) -C $(SHIM_DIR) all

.PHONY: format
format:
	$(MAKE) -C $(SHIM_DIR) format

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

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

.SECONDARY: $(BUILD_DIR)/Build.runtimedir
$(GLIBC_RUNTIME): $(BUILD_DIR)/Build.runtimedir
$(BUILD_DIR)/Build.runtimedir: $(GLIBC_TARGET)
	for f in $(abspath $(GLIBC_TARGET)); do \
		ln -sf $$f $(RUNTIME_DIR)/$$(basename $$f); \
	done && touch $@

GLIBC_MIRRORS ?= https://ftp.gnu.org/gnu/ \
		https://mirrors.kernel.org/gnu/ \
		https://mirrors.ocf.berkeley.edu/gnu/

ifeq ($(shell git ls-files $(GLIBC_SRC)/configure),)
$(GLIBC_SRC)/configure: $(GLIBC_SRC).patch
	[ -f $(GLIBC_SRC).tar.gz ] || \
	for MIRROR in $(GLIBC_MIRRORS); do \
		wget --timeout=10 $${MIRROR}glibc/$(GLIBC_SRC).tar.gz \
		&& break; \
	done
	[ "`sha256sum $(GLIBC_SRC).tar.gz`" = "$(GLIBC_CHECKSUM)  $(GLIBC_SRC).tar.gz" ] || \
		(echo "*** $(GLIBC_SRC).tar.gz has a wrong checksum ***"; exit 255)
	tar -xzf $(GLIBC_SRC).tar.gz
	cd $(GLIBC_SRC) && patch -p1 < ../$(GLIBC_SRC).patch
	cd $(GLIBC_SRC) && patch -p1 < ../glibc-fix-warning.patch
	cd $(GLIBC_SRC) && patch -p1 < ../glibc-no-pie.patch
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
