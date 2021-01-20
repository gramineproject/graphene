# Build the manifest for R:
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files.

# Constants

# Installation location of R. By default, Graphene will run the system R executable.
R_HOME ?= /usr/lib/R
R_EXEC = $(R_HOME)/bin/exec/R

# Relative path to Graphene root
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(R_HOME)/lib
export LD_LIBRARY_PATH

.PHONY: all
all: R.manifest pal_loader
ifeq ($(SGX),1)
all: R.manifest.sgx R.sig R.token
endif

include ../../Scripts/Makefile.configs

# Generate manifest rules for R dependencies.
# We'll duplicate some Glibc libraries (which Graphene provides in a customized version), but
# there's no harm in this.
R_TARGETS = $(R_EXEC) $(R_HOME)/library/stats/libs/stats.so $(R_HOME)/modules/lapack.so
.INTERMEDIATE: trusted-libs
trusted-libs: ../common_tools/get_deps.sh
	../common_tools/get_deps.sh $(R_TARGETS) > $@

R.manifest: R.manifest.template trusted-libs
	(sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	     -e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	     -e 's|$$(R_HOME)|'"$(R_HOME)"'|g' \
	     -e 's|$$(R_EXEC)|'"$(R_EXEC)"'|g' \
	     -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	     $<; \
	cat trusted-libs) > $@

# R manifests for SGX:
#   Generating the SGX-specific manifest (R.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

%.manifest.sgx: %.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

R.sig: R.manifest.sgx

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: check
check: all
	./pal_loader ./R --slave --vanilla -f scripts/sample.r > OUTPUT 2> /dev/null
	@grep -q "success" OUTPUT && echo "[ Success 1/1 ]"
	@$(RM) OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT

.PHONY: distclean
distclean: clean
