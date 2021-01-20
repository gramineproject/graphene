# Build Addressbook (official example of Cap'n Proto) as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations downloads the sample from the official GitHub repo
# (version 0.7.0) and builds it per official instructions. Note that capnproto
# and libcapnp.so must be already installed on the system.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the Addressbook sources.

# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

SRCDIR = src
CAPNPROTO_SRC_URL ?= https://raw.githubusercontent.com/capnproto/capnproto/v0.7.0

ADDRESSBOOK_SRC_URL    ?= $(CAPNPROTO_SRC_URL)/c%2B%2B/samples/addressbook.c%2B%2B
ADDRESSBOOK_SRC_SHA256 ?= d01f6d40b27aab93b53c7e58a81aa4eab927331e4390e5a7e778c163d30def82

ADDRESSBOOK_CAP_URL    ?= $(CAPNPROTO_SRC_URL)/c%2B%2B/samples/addressbook.capnp
ADDRESSBOOK_CAP_SHA256 ?= cf309b8b277881c95aaa785f4d0154f46f82575fdb9dea49fb10ee072b7c3ae6

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: addressbook addressbook.manifest pal_loader
ifeq ($(SGX),1)
all: addressbook.manifest.sgx addressbook.sig addressbook.token
endif

include ../../Scripts/Makefile.configs

$(SRCDIR)/addressbook.c++:
	mkdir -p $(SRCDIR)
	$(GRAPHENEDIR)/Scripts/download --output $(SRCDIR)/addressbook.c++ \
		--sha256 $(ADDRESSBOOK_SRC_SHA256) --url $(ADDRESSBOOK_SRC_URL)

$(SRCDIR)/addressbook.capnp:
	mkdir -p $(SRCDIR)
	$(GRAPHENEDIR)/Scripts/download --output $(SRCDIR)/addressbook.capnp \
		--sha256 $(ADDRESSBOOK_CAP_SHA256) --url $(ADDRESSBOOK_CAP_URL)

$(SRCDIR)/addressbook: $(SRCDIR)/addressbook.c++ $(SRCDIR)/addressbook.capnp
	cd $(SRCDIR) && capnp compile -oc++ addressbook.capnp
	cd $(SRCDIR) && c++ -std=c++14 -Wall addressbook.c++ addressbook.capnp.c++ \
	                    `pkg-config --cflags --libs capnp` -o addressbook

# Generate manifest rules for Addressbook dependencies.
# We'll duplicate some Glibc libraries (which Graphene provides in a customized version), but
# there's no harm in this.
.INTERMEDIATE: trusted-libs
trusted-libs: ../common_tools/get_deps.sh $(SRCDIR)/addressbook
	../common_tools/get_deps.sh $(SRCDIR)/addressbook > $@


addressbook.manifest: addressbook.manifest.template trusted-libs
	(sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$<; \
	cat trusted-libs) > $@

addressbook.manifest.sgx: addressbook.manifest addressbook
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

addressbook.sig: addressbook.manifest.sgx

addressbook.token: addressbook.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $^

addressbook: $(SRCDIR)/addressbook
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader addressbook

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR)
