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

GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
PYTHON3 ?= /usr/bin/python3

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

DISTRIB_ID ?= $(shell lsb_release --short --id)
DISTRIB_RELEASE ?= $(shell lsb_release --short --release)

ifeq ($(SGX), 1)
ifneq ($(DISTRIB_ID),Ubuntu)
$(error This example requires Ubuntu when building for SGX.)
endif
endif

UBUNTU_VERSION = $(DISTRIB_ID)$(DISTRIB_RELEASE)

.PHONY: all
all: python3.manifest python3_child.manifest | python3 python3_child pal_loader
ifeq ($(SGX),1)
all: python3.token python3_child.token
endif

include ../../Scripts/Makefile.configs

python3.sig: python3_child.sig

# .manifest.template contains stanzas for both Ubuntu 16 and 18. The last rule selectively enables
# those lines based on the Ubuntu version detected.
%.manifest: %.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(HOME)|'"$(HOME)"'|g' \
		-e 's|# '"$(UBUNTU_VERSION)"' ||g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

python3.sig: python3.manifest | python3
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec python3 \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-output python3.manifest.sgx \
		-manifest python3.manifest

%.token: %.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

# The PyTorch workload forks/execve()s at some point. Having two manifests is a workaround until
# Graphene fixes its loader.
python3_child.manifest: python3.manifest
	cp $< $@
	sed -i '/trusted_children/d' $@

python3_child.sig: python3_child python3_child.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-exec python3 \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-output python3_child.manifest.sgx \
		-manifest python3_child.manifest

python3 python3_child:
	ln -s $(PYTHON3) $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: download_model
download_model:
	$(PYTHON3) download-pretrained-model.py

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest python3 python3_child pal_loader

.PHONY: distclean
distclean: clean
	$(RM) *.pt result.txt
