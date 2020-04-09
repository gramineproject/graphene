# Build mbedTLS client/server example with RA-TLS as follows:
#
# - make          -- create SGX no-debug-log manifest
# - make DEBUG=1  -- create SGX debug-log manifest
#
# Any of these invocations clones mbedTLS' git repository (version 2.21.0) and
# builds it in default configuration. Also, server and client programs are
# built. See README for details.
#
# Use `make clean` to remove Graphene-generated files and `make distclean` to
# additionally remove the cloned mbedTLS git repository.

# Relative path to Graphene root
GRAPHENEDIR ?= ../..
GRAPHENEKEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

# Specify your SPID and linkable/unlinkable attestation policy
RA_CLIENT_SPID ?= AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
RA_CLIENT_LINKABLE ?= 0

ifeq ($(DEBUG),1)
GRAPHENEDEBUG=inline
CFLAGS += -O0 -ggdb3
else
GRAPHENEDEBUG=none
CFLAGS += -O2
endif

.PHONY: all
all: mbedtls/CMakeLists.txt server.manifest.sgx client pal_loader \
	 libra_tls_attest.so libra_tls_verify.so

############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= https://github.com/ARMmbed/mbed-crypto/archive/
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) \
		--sha256 $(MBEDTLS_CHECKSUM)

$(MBEDCRYPTO_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) \
		--sha256 $(MBEDCRYPTO_CHECKSUM)

mbedtls/CMakeLists.txt: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
	tar -mxzf $(MBEDTLS_SRC)
	tar -mxzf $(MBEDCRYPTO_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	$(RM) -r mbedtls/crypto
	mv mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls
	mv mbedtls/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls/crypto
	mkdir mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make SHARED=1 DESTDIR=install install .

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += -I./mbedtls/install/include -I./mbedtls/crypto/include \
		  -I$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls
LFLAGS += -Wl,-rpath,. -L. -lmbedcrypto -lmbedtls -lmbedx509

server: src/server.c libmbedcrypto.so libmbedtls.so libmbedx509.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

client: src/client.c libmbedcrypto.so libmbedtls.so libmbedx509.so libra_tls_verify.so libsgx_util.so
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@ -lsgx_util -lra_tls_verify

########################### COPIES FOR CONVENIENCE ############################

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/$@ .

libmbedcrypto.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libmbedtls.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libmbedx509.so: mbedtls/CMakeLists.txt
	cp mbedtls/install/lib/$@.* .
	ln -s $@.* $@

libsgx_util.so:
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/common/$@ .

libra_tls_attest.so:
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/$@ .

libra_tls_verify.so: libmbedcrypto.so libmbedx509.so libsgx_util.so
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/$@ .

############################### SERVER MANIFEST ###############################

server.manifest: server.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(RA_CLIENT_SPID)|'"$(RA_CLIENT_SPID)"'|g' \
		-e 's|$$(RA_CLIENT_LINKABLE)|'"$(RA_CLIENT_LINKABLE)"'|g' \
		$< > $@

server.manifest.sgx: server.manifest server libra_tls_attest.so
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEKEY) \
		-manifest $< -output $@ \
		-exec server
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output server.token -sig server.sig

################################## SGX CHECK ##################################

.PHONY: check
check: all
	SGX=1 ./pal_loader server & SERVER_ID=$$!; \
	sleep 30; \
	LD_PRELOAD=$(PWD)/libra_tls_verify.so ./client > OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 1/1 ]"
	@rm OUTPUT

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest pal_loader server client *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls *.tar.gz
