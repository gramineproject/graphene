ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: python.manifest
ifeq ($(SGX),1)
all: python.manifest.sgx python.sig python.token
endif

python.manifest: python.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		$< >$@

python.manifest.sgx: python.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

python.sig: python.manifest.sgx

python.token: python.sig
	graphene-sgx-get-token --output $@ --sig $<

.PHONY: check
check: all
	./run-tests.sh > TEST_STDOUT 2> TEST_STDERR
	@grep -q "Success 1/4" TEST_STDOUT
	@grep -q "Success 2/4" TEST_STDOUT
	@grep -q "Success 3/4" TEST_STDOUT
	@grep -q "Success 4/4" TEST_STDOUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR
	$(RM) -r scripts/__pycache__

.PHONY: distclean
distclean: clean
