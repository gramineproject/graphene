# Build the manifest for LMBench (only tested for version 2.5):
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files or `make distclean` to
# remove all generated or downloaded files from the directory.

# Constants

LMBENCHURLS = https://sourceforge.net/projects/lmbench/files/lmbench/2.5/lmbench-2.5.tgz/download \
	https://fossies.org/linux/privat/old/lmbench-2.5.tgz \
	https://borysp.com/lmbench-2.5.tgz
LMBENCHHASH = e7431530a4cf4c44b5068e23454f95765dc0b51e7d98bc2bd70451b17d505bd9
LMBENCHDIR = lmbench-2.5
INSTALLDIR = $(LMBENCHDIR)/bin/linux
LMBENCHCONFIG = $(INSTALLDIR)$(shell $(LMBENCHDIR)/scripts/config)

# Relative path to Graphene root
GRAPHENEDIR ?= ../..

# If GRAPHENEDIR is a relative path, extend the path from where LMBench is installed
ifeq ($(patsubst /%,,$(GRAPHENEDIR)),)
GRAPHENEDIR_FROM_INSTALLDIR = $(GRAPHENEDIR)
else
GRAPHENEDIR_FROM_INSTALLDIR = ../../../$(GRAPHENEDIR)
endif
SGX_SIGNER_KEY ?= $(GRAPHENEDIR_FROM_INSTALLDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

MANIFESTS = $(INSTALLDIR)/manifest $(INSTALLDIR)/hello.manifest $(INSTALLDIR)/sh.manifest

.PHONY: all
all: $(INSTALLDIR)/lmbench $(MANIFESTS) $(INSTALLDIR)/pal_loader
ifeq ($(SGX),1)
all: sgx
endif

include ../../Scripts/Makefile.configs

ifneq (,$(wildcard $(ARCH_LIBDIR)/libtirpc.so))
TIRPC_TRUSTED_LIBS=sgx.trusted_files.libtirpc = file:$(ARCH_LIBDIR)/libtirpc.so
endif

# Building LMBench binaries

$(INSTALLDIR)/lmbench: $(LMBENCHDIR)/src/Makefile
	$(MAKE) -C $(LMBENCHDIR)/src OS=linux

# Automatically downloading and unpacking LMBench source code
$(LMBENCHDIR)/src/Makefile: $(LMBENCHDIR).tgz
	tar -xzf $<
	touch $@
	cd $(LMBENCHDIR) && patch -p1 < ../patches/tirpc.patch
	cd $(LMBENCHDIR) && patch -p1 < ../patches/llseek.patch

$(LMBENCHDIR).tgz:
	$(GRAPHENEDIR)/Scripts/download --output $@ --sha256 $(LMBENCHHASH) $(foreach url,$(LMBENCHURLS),--url $(url))

$(INSTALLDIR)/lmbench-test-ci.sh:
	cp lmbench-test-ci.sh $@


# Generating the manifests

$(MANIFESTS): $(INSTALLDIR)/%: %.template $(INSTALLDIR)/lmbench
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR_FROM_INSTALLDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARCH_LONG)|'"$(ARCH_LONG)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		-e 's|$$(TIRPC_TRUSTED_LIBS)|'"$(TIRPC_TRUSTED_LIBS)"'|g' \
		$< > $@

# Generating the manifests for SGX
#
# For each program in LMBench, we need to generate the manifest
# individually, along with the signature and the inittoken.
#
# The 'sgx' rule below will list the executables in $(INSTALLDIR)
# and generate their manifests for SGX.

.PHONY: sgx
sgx: $(INSTALLDIR)/lmbench $(INSTALLDIR)/sh.manifest.sgx $(INSTALLDIR)/hello.manifest.sgx
	cd $(INSTALLDIR) && \
	for f in `find -executable -not -name . -not -name lmbench -not -name hello`; do \
		if [ ! -f $$f.manifest.sgx ]; then \
			$(GRAPHENEDIR_FROM_INSTALLDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
				-libpal $(GRAPHENEDIR_FROM_INSTALLDIR)/Runtime/libpal-Linux-SGX.so \
				-key $(SGX_SIGNER_KEY) \
				-manifest manifest -exec $$f -output $$f.manifest.sgx && \
			$(GRAPHENEDIR_FROM_INSTALLDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
				-output $$f.token -sig $$f.sig; \
		fi; \
	done

$(INSTALLDIR)/sh.manifest.sgx $(INSTALLDIR)/hello.manifest.sgx: %.sgx: %
	cd $(INSTALLDIR) && \
	$(GRAPHENEDIR_FROM_INSTALLDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR_FROM_INSTALLDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $(abspath $<) -output $(abspath $@) && \
	$(GRAPHENEDIR_FROM_INSTALLDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $(abspath $(basename $<).token) -sig $(abspath $(basename $<).sig)

# Running LMBench natively and under Graphene
#
# - make run-native:   run the whole test suite natively (with configuration prompt)
# - make run-graphene: run the whole test suite under Graphene (with configuration prompt)
# - make test:         run LMBench for CI (without configuration prompt)

$(LMBENCHCONFIG):
	cd $(LMBENCHDIR)/scripts && env OS=linux ./config-run

.PHONY: run-native
run-native: all $(LMBENCHCONFIG)
	cd $(LMBENCHDIR)/scripts && env OS=linux ./results

.PHONY: run-graphene
run-graphene: all $(LMBENCHCONFIG)
	cd $(LMBENCHDIR)/scripts && env LOADER=./pal_loader OS=linux RESULTS=results/graphene ./results

.PHONY: test
test: all $(INSTALLDIR)/lmbench-test-ci.sh
	cd $(INSTALLDIR) && env LOADER=./pal_loader OS=linux ./lmbench-test-ci.sh

$(INSTALLDIR)/pal_loader:
	ln -s $(GRAPHENEDIR_FROM_INSTALLDIR)/Runtime/pal_loader $@

.PHONY: clean
clean:
	[ ! -d $(INSTALLDIR) ] || (cd $(INSTALLDIR) && $(RM) *.manifest *.manifest.sgx *.sig *.token)

.PHONY: distclean
distclean: clean
	$(RM) -r $(LMBENCHDIR) $(LMBENCHDIR).tgz
