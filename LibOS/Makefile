include ../Scripts/Makefile.configs
include ../Scripts/Makefile.rules

GLIBC_VERSION ?= 2.31
GLIBC_SRC = glibc-$(GLIBC_VERSION)
GLIBC_CHECKSUM = $(firstword $(shell grep $(GLIBC_SRC).tar.gz glibc-checksums))
SHIM_DIR = shim
BUILD_DIR = glibc-build
RUNTIME_DIR = $(CURDIR)/../Runtime
GLIBC_LIBS = \
	csu/crt1.o \
	csu/crti.o \
	csu/crtn.o \
	dlfcn/libdl.so.2 \
	elf/ld-linux-x86-64.so.2 \
	libc.so \
	libc.so.6 \
	libos/liblibos.so.1 \
	login/libutil.so.1 \
	math/libm.so.6 \
	nptl/libpthread.so.0 \
	nptl_db/libthread_db.so.1 \
	resolv/libnss_dns.so.2 \
	resolv/libresolv.so.2 \
	rt/librt.so.1
GLIBC_TARGET = $(addprefix $(BUILD_DIR)/, $(GLIBC_LIBS))
GLIBC_RUNTIME = $(addprefix $(RUNTIME_DIR)/, $(notdir $(GLIBC_TARGET)))

GLIBC_CFLAGS = -O2 -U_FORTIFY_SOURCE -fno-stack-protector -Wno-unused-value
ifeq ($(DEBUG),1)
	GLIBC_CFLAGS += -g
endif
export GLIBC_CFLAGS

.PHONY: all
all: $(GLIBC_TARGET) $(GLIBC_RUNTIME)
	$(MAKE) -C $(SHIM_DIR) all

.PHONY: format
format:
	$(MAKE) -C $(SHIM_DIR) format

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

.SECONDARY: $(BUILD_DIR)/Build.success

$(BUILD_DIR)/Build.success: $(BUILD_DIR)/Makefile
	@echo "Building glibc, may take a while to finish. Warning messages may show up. If this process terminates with failures, see \"$(BUILD_DIR)/build.log\" for more information."
	($(MAKE) -C $(BUILD_DIR) 2>&1 >> build.log) && touch $@

$(GLIBC_TARGET): $(BUILD_DIR)/Build.success

$(BUILD_DIR)/Makefile: $(GLIBC_SRC)/configure
	mkdir -p $(BUILD_DIR)
	(cd $(BUILD_DIR) || exit 1; \
	CFLAGS=$$GLIBC_CFLAGS ../$< --prefix=$(RUNTIME_DIR) \
		--with-tls \
		--without-selinux \
		--disable-test \
		--disable-nscd \
	)

define LN_SF_TO_RUNTIME_DIR_template =
$(RUNTIME_DIR)/$(notdir $(1)): $(1)
	$$(call cmd,ln_sf)
endef

$(foreach lib,$(GLIBC_TARGET),$(eval $(call LN_SF_TO_RUNTIME_DIR_template,$(lib))))

GLIBC_MIRRORS ?= https://ftp.gnu.org/gnu/ \
		https://mirrors.kernel.org/gnu/ \
		https://mirrors.ocf.berkeley.edu/gnu/

GLIBC_PATCHES = \
	glibc-patches/$(GLIBC_SRC).patch \
	glibc-patches/syscalldb-api.patch \
	glibc-patches/liblibos.patch

GLIBC_PATCHES_2.23 = \
	glibc-patches/hp-timing-2.23+.patch \
	glibc-patches/dangling-else.patch \
	glibc-patches/cvs-common-symbols.patch \
	glibc-patches/rpc-format-overflow.patch \
	glibc-patches/ieee754-boolean-context.patch \
	glibc-patches/nis-bogus-conditional.patch

GLIBC_PATCHES_2.27 = \
	glibc-patches/hp-timing-2.23+.patch

GLIBC_PATCHES_2.31 = \
	glibc-patches/hp-timing-2.31.patch

ifneq ($(filter %.gold,$(shell readlink -f /usr/bin/ld)),)
GLIBC_PATCHES += glibc-patches/ld-gold.patch
endif

GLIBC_PATCHES += $(GLIBC_PATCHES_$(GLIBC_VERSION))

$(GLIBC_SRC)/configure: $(GLIBC_PATCHES) $(GLIBC_SRC).tar.gz
	$(RM) -r $(GLIBC_SRC)
	tar -xzf $(GLIBC_SRC).tar.gz
	cd $(GLIBC_SRC) && \
	for p in $(GLIBC_PATCHES); do \
		echo applying $$p; \
		patch -p1 < ../$$p || exit 255; \
	done
	touch $@

$(GLIBC_SRC).tar.gz:
	../Scripts/download --output $@ --sha256 $(GLIBC_CHECKSUM) $(foreach mirror,$(GLIBC_MIRRORS),--url $(mirror)glibc/$(GLIBC_SRC).tar.gz)

$(GLIBC_SRC)/elf/Versions: $(GLIBC_SRC)/configure

$(GLIBC_SRC)/nptl/Versions: $(GLIBC_SRC)/configure

$(GLIBC_SRC)/dlfcn/Versions: $(GLIBC_SRC)/configure

.PHONY: clean_
clean_:
	$(RM) -r $(BUILD_DIR) $(GLIBC_SRC) build.log

.PHONY: clean
clean: clean_
	$(MAKE) -C $(SHIM_DIR) clean

.PHONY: distclean
distclean: clean_
	$(MAKE) -C $(SHIM_DIR) distclean
	$(RM) $(GLIBC_SRC).tar.gz

else
.IGNORE: $(GLIBC_TARGET)
$(GLIBC_TARGET):

.PHONY: clean
clean:
	$(RM) -r $(BUILD_DIR)

.PHONY: distclean
distclean: clean
endif

.PHONY: test
test:
	$(MAKE) -C $(SHIM_DIR) test

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C $(SHIM_DIR) sgx-tokens
