ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

SRCDIR = src
MEMCACHED_SRC ?= memcached-1.5.21.tar.gz
MEMCACHED_MIRRORS ?= \
    https://memcached.org/files \
    https://packages.grapheneproject.io/distfiles

MEMCACHED_SHA256 ?= e3d10c06db755b220f43d26d3b68d15ebf737a69c7663529b504ab047efe92f4

UBUNTU_VER = $(shell lsb_release --short --id)$(shell lsb_release --short --release)

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: memcached memcached.manifest
ifeq ($(SGX),1)
all: memcached.manifest.sgx memcached.sig memcached.token
endif

$(SRCDIR)/configure:
	../common_tools/download --output memcached.tar.gz --sha256 $(MEMCACHED_SHA256) \
		$(foreach mirror,$(MEMCACHED_MIRRORS),--url $(mirror)/$(MEMCACHED_SRC))
	mkdir $(SRCDIR)
	tar -C $(SRCDIR) --strip-components=1 -xf memcached.tar.gz

$(SRCDIR)/memcached: $(SRCDIR)/configure
	cd $(SRCDIR) && ./configure
	$(MAKE) -C $(SRCDIR)

memcached.manifest: memcached.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

memcached.manifest.sgx: memcached.manifest memcached
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

memcached.sig: memcached.manifest.sgx

memcached.token: memcached.sig
	graphene-sgx-get-token \
		--output memcached.token --sig memcached.sig

# for simplicity, copy memcached executable into our root directory
memcached: $(SRCDIR)/memcached
	cp $< $@

.PHONY: start-native-server
start-native-server: all
	./memcached

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: start-graphene-server
start-graphene-server: all
	$(GRAPHENE) memcached -u nobody

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest memcached .lck

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) memcached.tar.gz
