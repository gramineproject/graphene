THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

INSTALL_DIR ?= $(THIS_DIR)install

LIGHTTPD_SRC ?= $(THIS_DIR)lighttpd-1.4.54
LIGHTTPD_HASH ?= 5151d38cb7c4c40effa13710e77ebdbef899f945b062cf32befc02d128ac424c

LIGHTTPD_MIRRORS ?= \
	https://download.lighttpd.net/lighttpd/releases-1.4.x/

# Host and port on which lighttpd listens
HOST ?= 127.0.0.1
PORT ?= 8003

# Relative path to Graphene root
GRAPHENEDIR ?= $(THIS_DIR)../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

GREP = grep
SED  = sed
LDD  = ldd
AWK  = awk

CONF_FILES = lighttpd-server.conf lighttpd.conf

.PHONY: all
all: $(INSTALL_DIR)/sbin/lighttpd lighttpd.manifest $(CONF_FILES) testdata | lighttpd pal_loader
ifeq ($(SGX),1)
all: lighttpd.token
endif

include ../../Scripts/Makefile.configs

# The commands for downloading and compiling the lighttpd source code, and
# installing the binaries.
$(INSTALL_DIR)/sbin/lighttpd: $(LIGHTTPD_SRC)/configure
	cd $(LIGHTTPD_SRC) && ./configure --prefix=$(abspath $(INSTALL_DIR)) \
		--without-openssl --without-pcre --without-zlib --without-bzip2
	cd $(LIGHTTPD_SRC) && $(MAKE)
	cd $(LIGHTTPD_SRC) && $(MAKE) install

$(LIGHTTPD_SRC)/configure: $(LIGHTTPD_SRC).tar.gz
	tar -xzf $<
	# Refresh the timestamp, but only for this file - otherwise ./configure starts recreating too
	# much.
	touch $(LIGHTTPD_SRC)/configure

$(LIGHTTPD_SRC).tar.gz:
	$(GRAPHENEDIR)/Scripts/download --output $@ --sha256 $(LIGHTTPD_HASH) $(foreach mirror,$(LIGHTTPD_MIRRORS),--url $(mirror)/$(LIGHTTPD_SRC).tar.gz)

# lighttpd dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libpthread libutil

LIGHTTPD_LIBS = $(INSTALL_DIR)/lib/mod_indexfile.so \
		$(INSTALL_DIR)/lib/mod_dirlisting.so \
		$(INSTALL_DIR)/lib/mod_staticfile.so

# Listing all the lighttpd dependencies, besides Glibc libraries
.INTERMEDIATE: lighttpd-deps
lighttpd-deps: $(INSTALL_DIR)/sbin/lighttpd
	@$(LDD) $(LIGHTTPD_LIBS) $(INSTALL_DIR)/sbin/lighttpd | \
		$(AWK) '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' | \
		sort | uniq | $($(GREP) -v -x $(patsubst %,-e %,$(GLIBC_DEPS))) > $@

# Generating manifest rules for lighttpd dependencies
.INTERMEDIATE: lighttpd-trusted-libs
lighttpd-trusted-libs: lighttpd-deps
	@LIGHTTPD_LIBS="$(LIGHTTPD_LIBS)" && \
	for F in `cat lighttpd-deps`; do \
		P=`$(LDD) $$LIGHTTPD_LIBS $(INSTALL_DIR)/sbin/lighttpd | $(GREP) $$F | $(AWK) '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

.INTERMEDIATE: lighttpd-trusted-mods
lighttpd-trusted-mods:
	@for F in $(LIGHTTPD_LIBS); do \
		N=`basename $$F .so | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$F\\\"\\\\n"; \
	done > $@

lighttpd.manifest: lighttpd.manifest.template lighttpd-trusted-libs lighttpd-trusted-mods
	@$(SED) -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(INSTALL_DIR)|'"$(INSTALL_DIR)"'|g' \
		-e 's|$$(INSTALL_DIR_ABSPATH)|'"$(abspath $(INSTALL_DIR))"'|g' \
		-e 's|$$(LIGHTTPD_TRUSTED_MODS)|'"`cat lighttpd-trusted-mods`"'|g' \
		-e 's|$$(LIGHTTPD_TRUSTED_LIBS)|'"`cat lighttpd-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generate the SGX-specific manifest (lighttpd.manifest.sgx), the enclave signature, and the token
# for enclave initialization.
lighttpd.manifest.sgx: lighttpd.manifest $(INSTALL_DIR)/sbin/lighttpd | lighttpd
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec lighttpd \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest lighttpd.manifest -output $@

lighttpd.sig: lighttpd.manifest.sgx

lighttpd.token: lighttpd.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $^

lighttpd: $(INSTALL_DIR)/sbin/lighttpd
	ln -s $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

# lighttpd configuration and test data

lighttpd-server.conf:
	@$(RM) $@
	@echo "server.document-root       = \"$(abspath $(INSTALL_DIR))/html\""    >> $@
	@echo "server.port                = $(PORT)"            >> $@
	@echo "server.bind                = \"$(HOST)\""        >> $@

lighttpd.conf:
	@$(RM) $@
	@echo "include \"lighttpd-server.conf\""                >> $@
	@echo "include \"lighttpd-generic.conf\""               >> $@

# Generate variously-sized HTML files in $(RANDOM_DIR)
RANDOM_DIR = $(INSTALL_DIR)/html/random
RANDOM_FILES = \
	$(foreach n,1 2 3 4 5 6 7 8 9 10,2K.$n.html) \
	$(foreach n,1 2 3 4 5,10K.$n.html) \
	$(foreach n,1 2 3 4 5,100K.$n.html) \
	$(foreach n,1 2 3,1M.$n.html) \
	$(foreach n,1 2 3,10M.$n.html) \
	$(foreach n,1 2 3,100.$n.html)

TEST_DATA = $(addprefix $(RANDOM_DIR)/,$(RANDOM_FILES))

$(RANDOM_DIR)/%.html:
	mkdir -p $(RANDOM_DIR)
	dd if=/dev/urandom of=$@ count=1 bs=$(basename $(basename $(notdir $@))) status=none

.PHONY: testdata
testdata: $(TEST_DATA)

# Targets to run lighttpd

.PHONY: start-native-server
start-native-server: all
	$(INSTALL_DIR)/sbin/lighttpd -D -m $(INSTALL_DIR)/lib -f lighttpd.conf

.PHONY: start-graphene-server
start-graphene-server: all
	./pal_loader ./lighttpd -D -m $(INSTALL_DIR)/lib -f lighttpd.conf

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT result-* $(CONF_FILES) \
	      lighttpd pal_loader

.PHONY: distclean
distclean: clean
	$(RM) -r $(LIGHTTPD_SRC).tar.gz $(LIGHTTPD_SRC) $(INSTALL_DIR) $(TEST_DATA) *.pem
