SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: sqlite3.manifest
ifeq ($(SGX),1)
all: sqlite3.manifest.sgx sqlite3.sig sqlite3.token
endif

sqlite3.manifest: manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Dexecdir=$(shell dirname $(shell which sqlite3)) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

sqlite3.manifest.sgx: sqlite3.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest sqlite3.manifest \
		--output $@

sqlite3.sig: sqlite3.manifest.sgx

sqlite3.token: sqlite3.sig
	graphene-sgx-get-token --output sqlite3.token --sig sqlite3.sig

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: regression
regression: all
	@rm -f scripts/testdir/*

	$(GRAPHENE) sqlite3 scripts/testdir/test.db < scripts/create.sql
	@echo "[ Success 1/3 ]"

	$(GRAPHENE) sqlite3 scripts/testdir/test.db < scripts/update.sql
	@echo "[ Success 2/3 ]"

	$(GRAPHENE) sqlite3 scripts/testdir/test.db < scripts/select.sql > OUTPUT
	diff OUTPUT scripts/select.txt
	@echo "[ Success 3/3 ]"

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT scripts/testdir/*

.PHONY: distclean
distclean: clean
