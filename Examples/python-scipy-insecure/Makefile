# Use one of the following commands to build the manifest for Python3:
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files.

include ../../Scripts/Makefile.configs

# Python constants are declared in Makefile.python
include ../../Scripts/Makefile.python

# Relative path to Graphene root
SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

UBUNTU_VER = $(shell lsb_release --short --id)$(shell lsb_release --short --release)

.PHONY: all
all: python.manifest
ifeq ($(SGX),1)
all: python.manifest.sgx python.sig python.token
endif

python.manifest: python.toml.in
	graphene-manifest \
		-Dsgx=$(SGX) \
		-Ddebug_type=$(GRAPHENEDEBUG) \
		-Dentrypoint=$(PYTHONEXEC) \
		$< $@

# Python manifests for SGX:
#   Generating the SGX-specific manifest (python.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

python.manifest.sgx: python.manifest
	graphene-sgx-sign \
		-libpal $(RUNTIMEDIR)/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest python.manifest \
		-output $@

python.sig: python.manifest.sgx

python.token: python.sig
	graphene-sgx-get-token -output $@ -sig $<

.PHONY: check
check: all
	$(GRAPHENE) ./python scripts/test-numpy.py > OUTPUT 2> /dev/null
	@sleep 1  # to make sure Bash child processes flush output under Graphene-SGX
	@grep -q "dot: " OUTPUT && echo "[ Success 1/2 ]"
	@rm OUTPUT

	$(GRAPHENE) ./python scripts/test-scipy.py > OUTPUT 2> /dev/null
	@sleep 1
	@grep -q "cholesky: " OUTPUT && echo "[ Success 2/2 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT*
	$(RM) -r scripts/__pycache__

.PHONY: distclean
distclean: clean
