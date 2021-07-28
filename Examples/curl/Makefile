THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
CURL_DIR ?= /usr/bin

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: curl.manifest
ifeq ($(SGX),1)
all: curl.manifest.sgx curl.sig curl.token
endif

curl.manifest: curl.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Dhome=$(HOME) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dcurl_dir=$(CURL_DIR) \
		$< >$@

curl.manifest.sgx: curl.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest curl.manifest \
		--output $@

curl.sig: curl.manifest.sgx

curl.token: curl.sig
	graphene-sgx-get-token --output $@ --sig $^

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: check
check: all
	(cd test-docroot; exec python3 -m http.server -b 127.0.0.1 19111) & httpd_pid=$$!; \
	../../Scripts/wait_for_server 5 127.0.0.1 19111; \
	$(GRAPHENE) ./curl http://127.0.0.1:19111/ > OUTPUT; rc=$$?; \
	kill $$httpd_pid; exit $$rc

	@grep -q "Hello World" OUTPUT && echo "[ Success 1/1 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT

.PHONY: distclean
distclean: clean
