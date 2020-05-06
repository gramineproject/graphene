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
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(R_HOME)/lib
export LD_LIBRARY_PATH

.PHONY: all
all: R.manifest sh.manifest pal_loader
ifeq ($(SGX),1)
all: R.manifest.sgx R.sig R.token sh.manifest.sgx sh.sig sh.token
endif

include ../../Scripts/Makefile.configs

# R dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results of:
#    - $(R_HOME)/bin/exec/R
#    - $(R_HOME)/library/stats/libs/stats.so
#    - $(R_HOME)/modules/lapack.so

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libpthread

# Use the ldd result of R, stats.so, and lapack.so
R_TARGETS = $(R_EXEC) $(R_HOME)/library/stats/libs/stats.so $(R_HOME)/modules/lapack.so

# Listing all the R dependencies, besides Glibc libraries
.INTERMEDIATE: R-ldd
R-ldd:
	@for F in $(R_TARGETS); do ldd $$F >> $@ || exit 1; done

.INTERMEDIATE: R-deps
R-deps: R-ldd
	@cat $< | awk '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' \
		| sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generating manifest rules for R dependencies
.INTERMEDIATE: R-trusted-libs
R-trusted-libs: R-deps
	@R_LIBS="$(R_TARGETS)" && \
	for F in `cat R-deps`; do \
		P=`ldd $$R_LIBS | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = file:$$P\\\\n"; \
	done > $@

# R manifests:
#   For each dependency, generate a rule as follows:
#       sgx.trusted_files.xxxx = file:xxxx

R.manifest: R.manifest.template R-trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(R_HOME)|'"$(R_HOME)"'|g' \
		-e 's|$$(R_EXEC)|'"$(R_EXEC)"'|g' \
		-e 's|$$(R_TRUSTED_LIBS)|'"`cat R-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

sh.manifest: sh.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		$< > $@

# R manifests for SGX:
#   Generating the SGX-specific manifest (R.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

R.manifest.sgx: R.manifest sh.manifest.sgx
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

R.sig: R.manifest.sgx

R.token: R.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output R.token -sig R.sig

# sh.manifest.sgx is needed for R to run the shell for file clean-up
sh.manifest.sgx: sh.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

sh.sig: sh.manifest.sgx

sh.token: sh.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output sh.token -sig sh.sig

# Extra executables
pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader
