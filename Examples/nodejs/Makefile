THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
NODEJS_DIR ?= /usr/bin

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: nodejs.manifest
ifeq ($(SGX),1)
all: nodejs.manifest.sgx nodejs.sig nodejs.token
endif

nodejs.manifest: nodejs.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dnodejs_dir=$(NODEJS_DIR) \
		$< >$@

nodejs.manifest.sgx: nodejs.manifest helloworld.js
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

nodejs.sig: nodejs.manifest.sgx

nodejs.token: nodejs.sig
	graphene-sgx-get-token --output $@ --sig $<

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: check
check: all
	$(GRAPHENE) ./nodejs helloworld.js > OUTPUT
	@grep -q "Hello World" OUTPUT && echo "[ Success 1/1 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT

.PHONY: distclean
distclean: clean
