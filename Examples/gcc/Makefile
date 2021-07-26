THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

ARCH_LONG ?= $(shell $(CC) -dumpmachine)
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

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

# awk '{print $NF}' ...  print last field.
BINUTILS_VERSION ?= $(shell ld -v | awk '{print $$NF}')
GCC_MAJOR_VERSION ?= $(shell gcc -v 2>&1 | tail -n1 | awk '{print $$3}' | awk 'BEGIN {FS="."}{print $$1}')
GCC_LIB_PATH ?= /usr/lib/gcc/$(ARCH_LONG)

.PHONY: all
all: gcc.manifest test_files/bzip2.c test_files/gzip.c
ifeq ($(SGX),1)
all: gcc.manifest.sgx gcc.sig gcc.token
endif

%.manifest: %.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dgcc_lib_path=$(GCC_LIB_PATH) \
		-Dgcc_major_version=$(GCC_MAJOR_VERSION) \
		$< >$@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# we need to hack around.
gcc.sig gcc.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: gcc.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest gcc.manifest \
		--output gcc.manifest.sgx

%.token: %.sig
	graphene-sgx-get-token --output $@ --sig $<

test_files/bzip2.c:
	../common_tools/download --output $@ --sha256 $(BZIP2_HASH) $(foreach mirror,$(BZIP2_MIRRORS),--url $(mirror))

# the file hosted by the authors doesn't compile...
test_files/gzip_broken.c:
	../common_tools/download --output $@ --sha256 $(GZIP_HASH) $(foreach mirror,$(GZIP_MIRRORS),--url $(mirror))

test_files/gzip.c: test_files/gzip_broken.c test_files/gzip.patch
	patch test_files/gzip_broken.c -i test_files/gzip.patch -o $@

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: check
check: all
	@echo "\n\nCompiling hello.c..."
	$(GRAPHENE) gcc test_files/helloworld.c -o test_files/hello
	@chmod 755 test_files/hello
	-./test_files/hello
	$(RM) test_files/hello

	@echo "\n\nCompiling bzip2.c..."
	$(GRAPHENE) gcc test_files/bzip2.c -o test_files/bzip2
	@chmod 755 test_files/bzip2
	$(RM) bzip2.tmp
	@cp -f test_files/bzip2 test_files/bzip2.copy
	./test_files/bzip2 -z test_files/bzip2.copy
	./test_files/bzip2 -d test_files/bzip2.copy.bz2
	diff -q test_files/bzip2 test_files/bzip2.copy
	$(RM) test_files/bzip2 test_file/bzip2.copy

	@echo "\n\nCompiling gzip.c..."
	$(GRAPHENE) gcc test_files/gzip.c -o test_files/gzip
	@chmod 755 test_files/gzip
	@cp -f test_files/gzip test_files/gzip.copy
	./test_files/gzip test_files/gzip.copy
	./test_files/gzip -d test_files/gzip.copy.gz
	diff -q test_files/gzip test_files/gzip.copy
	$(RM) test_files/gzip test_files/gzip.copy

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.sig *.token
	$(RM) test_files/gzip.copy test_files/bzip2.copy

.PHONY: distclean
distclean: clean
	$(RM) test_files/gzip_broken.c test_files/bzip2.c test_files/gzip.c
