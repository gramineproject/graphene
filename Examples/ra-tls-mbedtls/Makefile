# Build mbedTLS client/server example with RA-TLS as follows:
#
# - make          -- build SGX version with apps built in release mode and no logs
# - make DEBUG=1  -- build SGX version with apps built in debug mode and with logs
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

ARCH_LIBDIR ?= /lib/x86_64-linux-gnu

# for EPID attestation, specify your SPID and linkable/unlinkable attestation policy;
# for DCAP/ECDSA attestation, specify SPID as empty string (linkable value is ignored)
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3
else
GRAPHENE_LOG_LEVEL = error
CFLAGS += -O2
endif

.PHONY: all
all: app epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: app
app: .mbedtls_built server.manifest.sgx server.sig server.token client pal_loader

.PHONY: epid
epid: .epid_libs_copied client_epid.manifest.sgx client_epid.sig client_epid.token

.PHONY: dcap
dcap: .dcap_libs_copied client_dcap.manifest.sgx client_dcap.sig client_dcap.token

############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.grapheneproject.io/distfiles
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= \
	https://github.com/ARMmbed/mbed-crypto/archive \
	https://packages.grapheneproject.io/distfiles
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_CHECKSUM)

$(MBEDCRYPTO_SRC):
	$(GRAPHENEDIR)/Scripts/download --output $@ $(foreach mirror,$(MBEDCRYPTO_URI),--url $(mirror)/$(MBEDCRYPTO_SRC)) --sha256 $(MBEDCRYPTO_CHECKSUM)

.SECONDARY: .mbedtls_downloaded
.mbedtls_downloaded: $(MBEDTLS_SRC) $(MBEDCRYPTO_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDCRYPTO_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	$(RM) -r mbedtls/crypto
	mv mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls
	mv mbedtls/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) mbedtls/crypto
	touch $@

.SECONDARY: .mbedtls_configured
.mbedtls_configured: .mbedtls_downloaded
	mkdir -p mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C MBEDTLS_ERROR_C
	touch $@

.SECONDARY: .mbedtls_built
.mbedtls_built: .mbedtls_configured
	$(MAKE) -C mbedtls SHARED=1 DESTDIR=install install .
	touch $@

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += -I./mbedtls/install/include -I./mbedtls/crypto/include
LFLAGS += -Wl,-rpath,. -L./libs/ -ldl -lmbedcrypto -lmbedtls -lmbedx509

server: src/server.c .mbedtls_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

client: src/client.c .mbedtls_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

########################### COPIES FOR CONVENIENCE ############################

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/$@ .

.SECONDARY: .mbedtls_libs_copied
.mbedtls_libs_copied: .mbedtls_built
	mkdir -p libs

	cd libs                                        && \
	cp ../mbedtls/install/lib/libmbedcrypto.so.* . && \
	ln -s libmbedcrypto.so.* libmbedcrypto.so      && \
	cp ../mbedtls/install/lib/libmbedtls.so.* .    && \
	ln -s libmbedtls.so.* libmbedtls.so            && \
	cp ../mbedtls/install/lib/libmbedx509.so.* .   && \
	ln -s libmbedx509.so.* libmbedx509.so

	touch $@

.SECONDARY: .epid_libs_copied
.epid_libs_copied:
	mkdir -p libs
	cp -f $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/common/libsgx_util.so libs/
	cp -f $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_attest.so libs/
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_verify_epid.so libs/
	touch $@

.SECONDARY: .dcap_libs_copied
.dcap_libs_copied:
	mkdir -p libs
	cp -f $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/common/libsgx_util.so libs/
	cp -f $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_attest.so libs/
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_verify_dcap.so libs/
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libra_tls_verify_dcap_graphene.so libs/
	touch $@


############################### SERVER MANIFEST ###############################

server.manifest: server.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		-e 's|$$(RA_CLIENT_SPID)|'"$(RA_CLIENT_SPID)"'|g' \
		-e 's|$$(RA_CLIENT_LINKABLE)|'"$(RA_CLIENT_LINKABLE)"'|g' \
		$< > $@

server.manifest.sgx: server.manifest server .mbedtls_built .epid_libs_copied
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEKEY) \
		-manifest $< -output $@

server.sig: server.manifest.sgx

server.token: server.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

########################### CLIENT (DCAP) MANIFEST ############################

client_dcap.manifest: client.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    $< >$@

client_dcap.manifest.sgx: client_dcap.manifest client .mbedtls_built .dcap_libs_copied
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEKEY) \
		-manifest $< \
		-output $@

client_dcap.sig: client_dcap.manifest.sgx

client_dcap.token: client_dcap.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

########################### CLIENT (EPID) MANIFEST ############################

client_epid.manifest: client.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	    -e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	    -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	    $< >$@

client_epid.manifest.sgx: client_epid.manifest client .epid_libs_copied
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(GRAPHENEKEY) \
		-manifest $< \
		-output $@

client_epid.sig: client_epid.manifest.sgx

client_epid.token: client_epid.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

############################### SGX CHECKS FOR CI #############################

.PHONY: check_epid
check_epid: app epid
	SGX=1 ./pal_loader server epid >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./libs; \
	./client epid > OUTPUT; \
	./client epid 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_epid_fail
check_epid_fail: app epid
	SGX=1 ./pal_loader server epid dummy-option >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./libs; \
	./client epid && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

.PHONY: check_dcap
check_dcap: app dcap
	SGX=1 ./pal_loader server dcap >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./libs; \
	./client dcap > OUTPUT; \
	./client dcap 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_dcap_fail
check_dcap_fail: app dcap
	SGX=1 ./pal_loader server dcap dummy-option >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):./libs; \
	./client dcap && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r *.token *.sig *.manifest.sgx *.manifest pal_loader server client *.so *.so.* OUTPUT \
	         libs/ .mbedtls_libs_copied .epid_libs_copied .dcap_libs_copied

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls *.tar.gz .mbedtls_downloaded .mbedtls_configured .mbedtls_built
