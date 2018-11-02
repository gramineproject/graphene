SYS ?= $(shell gcc -dumpmachine)
export SYS

export DEBUG

GLIBC_SRC = glibc-2.19
GLIBC_CHECKSUM = 18ad6db70724699d264add80b1f813630d0141cf3a3558b4e1a7c15f6beac796
SHIM_DIR = shim
BUILD_DIR = glibc-build
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/,libc.so.6 ld-linux-x86-64.so.2 libpthread.so.0 libm.so.6 libdl.so.2 libutil.so.1 crt1.o crti.o crtn.o liblibos.so.1 libnss_dns.so.2 libresolv.so.2)

.PHONY: all
all: $(GLIBC_TARGET)
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

GLIBC_MIRRORS ?= https://ftp.gnu.org/gnu/ \
		https://mirrors.kernel.org/gnu/ \
		https://mirrors.ocf.berkeley.edu/gnu/

ifeq ($(shell git ls-files $(GLIBC_SRC)/configure),)
GLIBC_PATCHES = \
	$(GLIBC_SRC).patch \
	glibc-fix-warning.patch \
	glibc-no-pie.patch

$(GLIBC_SRC)/configure: $(GLIBC_PATCHES) Makefile
	[ -f $(GLIBC_SRC).tar.gz ] || \
	for MIRROR in $(GLIBC_MIRRORS); do \
		wget --timeout=10 $${MIRROR}glibc/$(GLIBC_SRC).tar.gz \
		&& break; \
	done
	[ "`sha256sum $(GLIBC_SRC).tar.gz`" = "$(GLIBC_CHECKSUM)  $(GLIBC_SRC).tar.gz" ] || \
		(echo "*** $(GLIBC_SRC).tar.gz has a wrong checksum ***"; exit 255)
	tar -xzf $(GLIBC_SRC).tar.gz
	cd $(GLIBC_SRC) && \
	for p in $(GLIBC_PATCHES); do \
		echo applying $$p; \
		patch -p1 < ../$$p; \
	done
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
