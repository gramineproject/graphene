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
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY=all
all: addressbook addressbook.manifest pal_loader
ifeq ($(SGX),1)
all: addressbook.token
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

# Addressbook dependencies (from ldd); needed for concrete versions of libcapnp.so and libkj.so

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc binaries are
# already listed in the manifest template, so we can skip them from the ldd results.
GLIBC_DEPS = linux-vdso.so.1 /lib64/ld-linux-x86-64.so.2 libc.so.6 libm.so.6 librt.so.1 \
             libdl.so.2 libpthread.so.0 libutil.so.1 libresolv.so.2 libnss_dns.so.2

# List all Addressbook dependencies, besides Glibc libraries
.INTERMEDIATE: addressbook-deps
addressbook-deps: $(SRCDIR)/addressbook
	@ldd $(SRCDIR)/addressbook | \
		awk '{if ($$2 =="=>") {print $$1}}' | \
		sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generate manifest rules for Addressbook dependencies
.INTERMEDIATE: addressbook-trusted-libs
addressbook-trusted-libs: addressbook-deps
	@for F in `cat addressbook-deps`; do \
		P=`ldd $(SRCDIR)/addressbook | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '.' | tr --delete '-' | tr --delete '+'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

addressbook.manifest: addressbook.manifest.template addressbook-trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(TRUSTEDLIBS)|'"`cat addressbook-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

addressbook.manifest.sgx: addressbook.manifest addressbook
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@ \
		-exec $(SRCDIR)/addressbook

addressbook.sig: addressbook.manifest.sgx

addressbook.token: addressbook.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $@ -sig $^

addressbook: $(SRCDIR)/addressbook
	cp $< $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY=clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader addressbook

.PHONY=distclean
distclean: clean
	$(RM) -r $(SRCDIR)
