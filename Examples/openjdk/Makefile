ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

SOURCE_FILES = \
	MultiThreadMain.java

CLASS_FILES = $(SOURCE_FILES:.java=.class)

%.class: %.java
	javac -d . $<

.PHONY: all
all: $(CLASS_FILES) java.manifest
ifeq ($(SGX),1)
all: java.manifest.sgx java.sig java.token
endif

java.manifest: java.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v java")) \
		$< >$@

java.manifest.sgx: java.manifest
	@test -s $(SGX_SIGNER_KEY) || \
		{ echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

java.sig: java.manifest.sgx

java.token: java.sig
	graphene-sgx-get-token --output $@ --sig $<

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest *.class

.PHONY: distclean
distclean: clean
