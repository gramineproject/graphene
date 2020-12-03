# Use one of these commands to build the manifest for Node.js:
#
# - make
# - make DEBUG=1
# - make SGX=1
# - make SGX=1 DEBUG=1
#
# Use `make clean` to remove Graphene-generated files.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
NODEJS_DIR ?= /usr/bin/

# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: nodejs.manifest | nodejs pal_loader
ifeq ($(SGX),1)
all: nodejs.token
endif

include ../../Scripts/Makefile.configs

# Node.js dependencies (generated from ldd). For SGX, the manifest needs to list all the libraries
# loaded during execution, so that the signer can include the file hashes.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc binaries are
# already listed in the manifest template, so we can skip them from the ldd results.
GLIBC_DEPS = linux-vdso.so.1 /lib64/ld-linux-x86-64.so.2 libc.so.6 libm.so.6 librt.so.1 \
             libdl.so.2 libpthread.so.0 libutil.so.1 libresolv.so.2 libnss_dns.so.2

# List all the Node.js dependencies, besides Glibc libraries
.INTERMEDIATE: nodejs-deps
nodejs-deps:
	@ldd $(NODEJS_DIR)nodejs | \
		awk '{if ($$2 =="=>") {print $$1}}' | \
		sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generate manifest rules for Node.js dependencies
.INTERMEDIATE: nodejs-trusted-libs
nodejs-trusted-libs: nodejs-deps
	@for F in `cat nodejs-deps`; do \
		P=`ldd $(NODEJS_DIR)nodejs | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '.' | tr --delete '-' | tr --delete '+'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

nodejs.manifest: nodejs.manifest.template nodejs-trusted-libs
	@sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(NODEJS_DIR)|'"$(NODEJS_DIR)"'|g' \
		-e 's|$$(NODEJS_TRUSTED_LIBS)|'"`cat nodejs-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generate SGX-specific manifest, enclave signature, and token for enclave initialization
nodejs.manifest.sgx: nodejs.manifest helloworld.js
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec nodejs \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

nodejs.sig: nodejs.manifest.sgx

nodejs.token: nodejs.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

nodejs:
	ln -s $(NODEJS_DIR)nodejs $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: check
check: all
	./pal_loader ./nodejs helloworld.js > OUTPUT
	@grep -q "Hello World" OUTPUT && echo "[ Success 1/1 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig nodejs pal_loader OUTPUT

.PHONY: distclean
distclean: clean
