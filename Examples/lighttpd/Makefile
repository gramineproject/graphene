THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

INSTALL_DIR ?= $(THIS_DIR)install

LIGHTTPD_SRC ?= $(THIS_DIR)lighttpd-1.4.59
LIGHTTPD_HASH ?= e266e389ddb79bf17b8e8d9022aec95ae839c6f3159822f402df8d8df8a13f65

LIGHTTPD_MIRRORS ?= \
    https://download.lighttpd.net/lighttpd/releases-1.4.x \
    https://packages.grapheneproject.io/distfiles

HOST ?= 127.0.0.1
PORT ?= 8003

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

CONF_FILES = lighttpd-server.conf lighttpd.conf

.PHONY: all
all: $(INSTALL_DIR)/sbin/lighttpd lighttpd.manifest $(CONF_FILES) testdata
ifeq ($(SGX),1)
all: lighttpd.manifest.sgx lighttpd.sig lighttpd.token
endif

$(INSTALL_DIR)/sbin/lighttpd: $(LIGHTTPD_SRC)/configure
	cd $(LIGHTTPD_SRC) && ./configure --prefix=$(abspath $(INSTALL_DIR)) \
		--without-openssl --without-pcre --without-bzip2
	cd $(LIGHTTPD_SRC) && $(MAKE)
	cd $(LIGHTTPD_SRC) && $(MAKE) install

$(LIGHTTPD_SRC)/configure: $(LIGHTTPD_SRC).tar.gz
	tar -xzf $<
	# Refresh the timestamp, but only for this file - otherwise ./configure starts recreating too
	# much.
	touch $(LIGHTTPD_SRC)/configure

$(LIGHTTPD_SRC).tar.gz:
	../common_tools/download --output $@ --sha256 $(LIGHTTPD_HASH) \
		$(foreach mirror,$(LIGHTTPD_MIRRORS),--url $(mirror)/$(LIGHTTPD_SRC).tar.gz)

lighttpd.manifest: lighttpd.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dinstall_dir=$(INSTALL_DIR) \
		-Dinstall_dir_abspath=$(abspath $(INSTALL_DIR)) \
		$< >$@

lighttpd.manifest.sgx: lighttpd.manifest $(INSTALL_DIR)/sbin/lighttpd
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest lighttpd.manifest \
		--output $@

lighttpd.sig: lighttpd.manifest.sgx

lighttpd.token: lighttpd.sig
	graphene-sgx-get-token --output $@ --sig $^

# lighttpd configuration and test data
lighttpd-server.conf:
	@$(RM) $@
	@echo "server.document-root       = \"$(abspath $(INSTALL_DIR))/html\""    >> $@
	@echo "server.port                = $(PORT)"            >> $@
	@echo "server.bind                = \"$(HOST)\""        >> $@

lighttpd.conf:
	@$(RM) $@
	@echo "include \"./lighttpd-server.conf\""              >> $@
	@echo "include \"./lighttpd-generic.conf\""             >> $@

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

.PHONY: start-native-server
start-native-server: all
	$(INSTALL_DIR)/sbin/lighttpd -D -m $(INSTALL_DIR)/lib -f lighttpd.conf

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: start-graphene-server
start-graphene-server: all
	$(GRAPHENE) ./lighttpd -D -m $(INSTALL_DIR)/lib -f lighttpd.conf

.PHONY: clean
clean:
	$(RM) \
		*.manifest *.manifest.sgx *.token *.sig OUTPUT result-* $(CONF_FILES)

.PHONY: distclean
distclean: clean
	$(RM) -r $(LIGHTTPD_SRC).tar.gz $(LIGHTTPD_SRC) $(INSTALL_DIR) $(TEST_DATA) *.pem
