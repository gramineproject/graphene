THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Relative path to Graphene root
GRAPHENEDIR ?= $(THIS_DIR)/../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
BZIP2_MIRRORS ?= \
	https://people.csail.mit.edu/smcc/projects/single-file-programs/bzip2.c \
	https://packages.grapheneproject.io/distfiles/single-file-programs/bzip2.c
BZIP2_HASH ?= 89f331ce93cbf0ee7318802f440f1d7594bb78cf1a82069f2288e0459ec8d729
GZIP_MIRRORS ?= \
	https://people.csail.mit.edu/smcc/projects/single-file-programs/gzip.c \
	https://packages.grapheneproject.io/distfiles/single-file-programs/gzip.c
GZIP_HASH ?= 7ec7d87822e6497648580064756f64e47dbd085727910ebbc52a7c240a88dc27

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

include ../../Scripts/Makefile.configs

# awk '{print $NF}' ...  print last field.
BINUTILS_VERSION ?= $(shell ld -v | awk '{print $$NF}')
GCC_MAJOR_VERSION ?= $(shell gcc -v 2>&1 | tail -n1 | awk '{print $$3}' | awk 'BEGIN {FS="."}{print $$1}')
GCC_LIB_PATH ?= /usr/lib/gcc/$(ARCH_LONG)

.PHONY: all
all: gcc.manifest test_files/bzip2.c test_files/gzip.c | pal_loader
ifeq ($(SGX),1)
all: gcc.manifest.sgx gcc.sig gcc.token
endif

# Generate manifest rules for Bash dependencies.
# We'll duplicate some Glibc libraries (which Graphene provides in a customized version), but
# there's no harm in this.
PROGRAMS = /usr/bin/gcc \
           $(GCC_LIB_PATH)/$(GCC_MAJOR_VERSION)/cc1 \
           $(GCC_LIB_PATH)/$(GCC_MAJOR_VERSION)/collect2 \
           /usr/bin/as \
           /usr/bin/ld
.INTERMEDIATE: trusted-libs
trusted-libs: ../common_tools/get_deps.sh
	../common_tools/get_deps.sh $(PROGRAMS) > $@

%.manifest: %.manifest.template trusted-libs
	(sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
		-e 's|$$(BINUTILS_VERSION)|'"$(BINUTILS_VERSION)"'|g' \
		-e 's|$$(GCC_MAJOR_VERSION)|'"$(GCC_MAJOR_VERSION)"'|g' \
		-e 's|$$(GCC_LIB_PATH)|'"$(GCC_LIB_PATH)"'|g' \
		-e 's|$$(LD_TRUSTED_FILES)|'"`cat ld-gcc-$(GCC_MAJOR_VERSION)-trusted-files`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$<; \
	cat trusted-libs) > $@

# Rules to generate the SGX-specific manifest (.manifest.sgx), the enclave signature (.sig), and the
# enclave initialization token (.token).
gcc.sig gcc.manifest.sgx &: gcc.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest gcc.manifest \
		-output gcc.manifest.sgx

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

test_files/bzip2.c:
	$(GRAPHENEDIR)/Scripts/download --output $@ --sha256 $(BZIP2_HASH) $(foreach mirror,$(BZIP2_MIRRORS),--url $(mirror))

# the file hosted by the authors doesn't compile...
test_files/gzip_broken.c:
	$(GRAPHENEDIR)/Scripts/download --output $@ --sha256 $(GZIP_HASH) $(foreach mirror,$(GZIP_MIRRORS),--url $(mirror))

test_files/gzip.c: test_files/gzip_broken.c test_files/gzip.patch
	patch test_files/gzip_broken.c -i test_files/gzip.patch -o $@

.PHONY: check
check: all
	@echo "\n\nCompiling hello.c..."
	./pal_loader gcc test_files/helloworld.c -o test_files/hello
	@chmod 755 test_files/hello
	-./test_files/hello
	$(RM) test_files/hello

	@echo "\n\nCompiling bzip2.c..."
	./pal_loader gcc test_files/bzip2.c -o test_files/bzip2
	@chmod 755 test_files/bzip2
	$(RM) bzip2.tmp
	@cp -f test_files/bzip2 test_files/bzip2.copy
	./test_files/bzip2 -z test_files/bzip2.copy
	./test_files/bzip2 -d test_files/bzip2.copy.bz2
	diff -q test_files/bzip2 test_files/bzip2.copy
	$(RM) test_files/bzip2 test_file/bzip2.copy

	@echo "\n\nCompiling gzip.c..."
	./pal_loader gcc test_files/gzip.c -o test_files/gzip
	@chmod 755 test_files/gzip
	@cp -f test_files/gzip test_files/gzip.copy
	./test_files/gzip test_files/gzip.copy
	./test_files/gzip -d test_files/gzip.copy.gz
	diff -q test_files/gzip test_files/gzip.copy
	$(RM) test_files/gzip test_files/gzip.copy

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.sig *.token pal_loader trusted-libs
	$(RM) test_files/gzip.copy test_files/bzip2.copy

.PHONY: distclean
distclean: clean
	$(RM) test_files/gzip_broken.c test_files/bzip2.c test_files/gzip.c
