# Build PyTorch as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# PyTorch and the pre-trained model must be installed on the system.
# See README for details.
#
# Use `make clean` to remove Graphene-generated files.


include ../../Scripts/Makefile.configs

GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: pytorch.manifest
ifeq ($(SGX),1)
all: pytorch.manifest.sgx pytorch.sig pytorch.token
endif

%.manifest: %.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# we need to hack around.
pytorch.sig pytorch.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: pytorch.manifest
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--output pytorch.manifest.sgx \
		--manifest pytorch.manifest

%.token: %.sig
	graphene-sgx-get-token --output $@ --sig $<

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest

.PHONY: distclean
distclean: clean
	$(RM) *.pt result.txt
