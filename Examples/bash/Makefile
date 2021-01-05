# Use one of these commands to build the manifest for Bash:
#
# - make
# - make DEBUG=1
# - make SGX=1
# - make SGX=1 DEBUG=1
#
# Use `make clean` to remove Graphene-generated files.

# Listing the programs to be run inside the bash script
PROGRAMS = ls cat rm cp date

# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: bash.manifest $(addsuffix .manifest,$(PROGRAMS)) | bash $(PROGRAMS) pal_loader
ifeq ($(SGX),1)
all: bash.token $(addsuffix .token,$(PROGRAMS))
endif

include ../../Scripts/Makefile.configs

# Program dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results. This list also contains some runtime deps of Bash.
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libutil libpthread \
             libselinux libpcre libacl libattr

# Listing all Bash dependencies, besides Glibc libraries
.INTERMEDIATE: $(addsuffix .deps,bash $(PROGRAMS))
%.deps:
	ldd $(shell which $(basename $@)) | \
		awk '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' | \
		sort | uniq | (grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) || true) > $@

# Generating manifest rules for Bash dependencies
.INTERMEDIATE: $(addsuffix .trusted-libs,bash $(PROGRAMS))
%.trusted-libs: %.deps
	for F in `cat $<`; do \
		P=`ldd $(shell which $(basename $@)) | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

.INTERMEDIATE: trusted-children
trusted-children:
	@for F in $(PROGRAMS); do \
		echo -n "sgx.trusted_children.$$F = \\\"file:$$F.sig\\\"\\\\n"; \
		echo -n "sgx.trusted_files.$$F    = \\\"file:$$F\\\"\\\\n"; \
		done > $@

bash.manifest: manifest.template trusted-children bash.trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARGV0_OVERRIDE)|bash|g' \
		-e 's|$$(EXECDIR)|'"$(shell dirname $(shell which bash))"'|g' \
		-e 's|$$(TRUSTED_LIBS)|'"`cat bash.trusted-libs`"'|g' \
		-e 's|$$(TRUSTED_CHILDREN)|'"`cat trusted-children`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

$(addsuffix .manifest,$(PROGRAMS)): %.manifest: manifest.template %.trusted-libs
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(ARGV0_OVERRIDE)|'"$(basename $@)"'|g' \
		-e 's|$$(EXECDIR)|'"$(shell dirname $(shell which $(basename $@)))"'|g' \
		-e 's|$$(TRUSTED_LIBS)|'"`cat $(basename $@).trusted-libs`"'|g' \
		-e 's|$$(TRUSTED_CHILDREN)||g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generating the SGX-specific manifest (*.manifest.sgx), the enclave signature,
# and the token for enclave initialization.
bash.manifest.sgx: bash.manifest $(addsuffix .manifest.sgx,$(PROGRAMS)) | bash
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec bash \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest bash.manifest -output $@

bash.sig: bash.manifest.sgx

bash.token: bash.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output bash.token -sig bash.sig

$(addsuffix .manifest.sgx,$(PROGRAMS)): %.manifest.sgx: % %.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec $* \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $*.manifest \
		-output $@

$(addsuffix .sig,$(PROGRAMS)): %.sig: %.manifest.sgx

$(addsuffix .token,$(PROGRAMS)): %.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $(basename $<).token -sig $(basename $<).sig

bash $(PROGRAMS):
	ln -s "$(shell which $@)" $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: regression
regression: all
	@mkdir -p scripts/testdir

	./pal_loader ./bash -c "ls" > OUTPUT
	@grep -q "Makefile" OUTPUT && echo "[ Success 1/6 ]"
	@rm OUTPUT

	./pal_loader ./bash -c "cd scripts && bash bash_test.sh 1" > OUTPUT
	@grep -q "hello 1" OUTPUT      && echo "[ Success 2/6 ]"
	@grep -q "createdfile" OUTPUT  && echo "[ Success 3/6 ]"
	@grep -q "somefile" OUTPUT     && echo "[ Success 4/6 ]"
	@grep -q "current date" OUTPUT && echo "[ Success 5/6 ]"
	@rm OUTPUT

	./pal_loader ./bash -c "cd scripts && bash bash_test.sh 3" > OUTPUT
	@grep -q "hello 3" OUTPUT      && echo "[ Success 6/6 ]"
	@rm OUTPUT

	@rm -rf scripts/testdir


.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig bash $(PROGRAMS) pal_loader OUTPUT \
	      scripts/testdir/*

.PHONY: distclean
distclean: clean
