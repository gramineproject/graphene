# Use one of the following commands to build the manifests for Python:
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files.

include ../../Scripts/Makefile.configs

# Python constants are declared in Makefile.python
# We want to use Python 3.6 (default on Ubuntu 18.04)
PYTHONVERSION = python3.6
include ../../Scripts/Makefile.python

# Relative path to Graphene root
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: python3.6.manifest sh.manifest python3.manifest pal_loader
ifeq ($(SGX),1)
all: python3.6.manifest.sgx python3.6.sig python3.6.token sh.manifest.sgx sh.sig sh.token python3.manifest.sgx python3.sig python3.token
endif

python3.6.manifest: python3.6.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
	    -e 's|$$(PYTHONDISTHOME)|'"$(PYTHONDISTHOME)"'|g' \
	    -e 's|$$(PYTHONHOME)|'"$(PYTHONHOME)"'|g' \
	    -e 's|$$(PYTHONEXEC)|'"$(PYTHONEXEC)"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    -e 's|$$(SYS)|'"$(SYS)"'|g' \
	    $< > $@

python3.manifest: python3.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
	    -e 's|$$(PYTHONDISTHOME)|'"$(PYTHONDISTHOME)"'|g' \
	    -e 's|$$(PYTHONHOME)|'"$(PYTHONHOME)"'|g' \
	    -e 's|$$(PYTHONEXEC)|'"$(PYTHONEXEC)"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    -e 's|$$(SYS)|'"$(SYS)"'|g' \
	    $< > $@

sh.manifest: sh.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
	    $< > $@

# Python/sh manifests for SGX:
#   Generating the SGX-specific manifest (*.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

%.manifest.sgx: %.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

python3.6.sig: python3.6.manifest.sgx
python3.sig: python3.manifest.sgx
sh.sig: sh.manifest.sgx

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

python3.6.manifest.sgx: sh.sig
sh.manifest.sgx: python3.sig

# Extra executables
pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: check
check: all
	./pal_loader python3.6.manifest scripts/callprocess.py > OUTPUT 2> /dev/null
	@grep -q "helloworld" OUTPUT && echo "[ Success 1/2 ]"
	@grep -q "exit code of child process: 0" OUTPUT && echo "[ Success 2/2 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT*
	$(RM) -r scripts/__pycache__

.PHONY: distclean
distclean: clean
