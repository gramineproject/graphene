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

# Python constants are declared in Makefile.python
include ../../Scripts/Makefile.python

GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: pytorch.manifest | pal_loader
ifeq ($(SGX),1)
all: pytorch.manifest.sgx pytorch.sig pytorch.token
endif

%.manifest: %.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	    -e 's|$$(PYTHONDISTHOME)|'"$(PYTHONDISTHOME)"'|g' \
	    -e 's|$$(PYTHONHOME)|'"$(PYTHONHOME)"'|g' \
	    -e 's|$$(PYTHONEXEC)|'"$(PYTHONEXEC)"'|g' \
	    -e 's|$$(PYTHONSHORTVERSION)|'"$(PYTHONSHORTVERSION)"'|g' \
	    -e 's|$$(PYTHONVERSION)|'"$(PYTHONVERSION)"'|g' \
	    -e 's|$$(PYTHON_ARCH_LONG)|'"$(PYTHON_ARCH_LONG)"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    -e 's|$$(HOME)|'"$(HOME)"'|g' \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# we need to hack around.
pytorch.sig pytorch.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: pytorch.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-output pytorch.manifest.sgx \
		-manifest pytorch.manifest

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: download_model
download_model:
	$(PYTHONEXEC) download-pretrained-model.py

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader

.PHONY: distclean
distclean: clean
	$(RM) *.pt result.txt
