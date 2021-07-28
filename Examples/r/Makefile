# Installation location of R. By default, Graphene will run the system R executable.
R_HOME ?= /usr/lib/R
R_EXEC = $(R_HOME)/bin/exec/R

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(R_HOME)/lib
export LD_LIBRARY_PATH

.PHONY: all
all: R.manifest
ifeq ($(SGX),1)
all: R.manifest.sgx R.sig R.token
endif

R.manifest: R.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dr_home=$(R_HOME) \
		-Dr_exec=$(R_EXEC) \
		$< >$@

%.manifest.sgx: %.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

R.sig: R.manifest.sgx

%.token: %.sig
	graphene-sgx-get-token --output $@ --sig $<

ifeq ($(SGX),)
GRAPHENE = graphene-direct
else
GRAPHENE = graphene-sgx
endif

.PHONY: check
check: all
	$(GRAPHENE) ./R --slave --vanilla -f scripts/sample.r > OUTPUT 2> /dev/null
	@grep -q "success" OUTPUT && echo "[ Success 1/1 ]"
	@$(RM) OUTPUT

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT

.PHONY: distclean
distclean: clean
