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
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

CONF_FILES = lighttpd-server.conf lighttpd.conf

.PHONY: all
all: $(INSTALL_DIR)/sbin/lighttpd lighttpd.manifest $(CONF_FILES) testdata | pal_loader
ifeq ($(SGX),1)
all: lighttpd.manifest.sgx lighttpd.sig lighttpd.token
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

# Generate manifest rules for lighttpd dependencies.
# We'll duplicate some Glibc libraries (which Graphene provides in a customized version), but
# there's no harm in this.
PROGRAMS = $(INSTALL_DIR)/sbin/lighttpd \
           $(INSTALL_DIR)/lib/mod_indexfile.so \
           $(INSTALL_DIR)/lib/mod_dirlisting.so \
           $(INSTALL_DIR)/lib/mod_staticfile.so
.INTERMEDIATE: trusted-libs
trusted-libs: ../common_tools/get_deps.sh $(INSTALL_DIR)/sbin/lighttpd
	../common_tools/get_deps.sh $(PROGRAMS) > $@

lighttpd.manifest: lighttpd.manifest.template trusted-libs
	(sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	     -e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	     -e 's|$$(INSTALL_DIR)|'"$(INSTALL_DIR)"'|g' \
	     -e 's|$$(INSTALL_DIR_ABSPATH)|'"$(abspath $(INSTALL_DIR))"'|g' \
	     -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	     $<; \
	cat trusted-libs) > $@

# Generate the SGX-specific manifest (lighttpd.manifest.sgx), the enclave signature, and the token
# for enclave initialization.
lighttpd.manifest.sgx: lighttpd.manifest $(INSTALL_DIR)/sbin/lighttpd
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest lighttpd.manifest -output $@

lighttpd.sig: lighttpd.manifest.sgx

lighttpd.token: lighttpd.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $^

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
	      pal_loader

.PHONY: distclean
distclean: clean
	$(RM) -r $(LIGHTTPD_SRC).tar.gz $(LIGHTTPD_SRC) $(INSTALL_DIR) $(TEST_DATA) *.pem
