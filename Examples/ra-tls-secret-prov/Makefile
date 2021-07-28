GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

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

.PHONY: clients
clients: secret_prov_min_client secret_prov_client secret_prov_pf_client

.PHONY: all
all: app epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: app
app: mbedtls/.mbedtls_built \
     secret_prov_min_client.manifest.sgx secret_prov_min_client.sig secret_prov_min_client.token \
     secret_prov_client.manifest.sgx     secret_prov_client.sig     secret_prov_client.token     \
     secret_prov_pf_client.manifest.sgx  secret_prov_pf_client.sig  secret_prov_pf_client.token

.PHONY: epid
epid: secret_prov_server_epid libs/.epid_libs_copied

.PHONY: dcap
dcap: secret_prov_server_dcap libs/.dcap_libs_copied

############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 2.26.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.grapheneproject.io/distfiles
MBEDTLS_CHECKSUM ?= 35d8d87509cd0d002bddbd5508b9d2b931c5e83747d087234cc7ad551d53fe05

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	../common_tools/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_CHECKSUM)

.SECONDARY: mbedtls/.mbedtls_downloaded
mbedtls/.mbedtls_downloaded: $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	touch $@

.SECONDARY: mbedtls/.mbedtls_configured
mbedtls/.mbedtls_configured: mbedtls/.mbedtls_downloaded
	mkdir -p mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C
	touch $@

.SECONDARY: mbedtls/.mbedtls_built
mbedtls/.mbedtls_built: mbedtls/.mbedtls_configured
	$(MAKE) -C mbedtls SHARED=1 DESTDIR=install install .
	touch $@

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += -Wall -std=c11 -I$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls
# These flags are *NOT* for production, setting rpath is here only to simplify the test setup.
LFLAGS += -Wl,-rpath-link,./libs/ -L./libs/ -lmbedcrypto -lmbedtls -lmbedx509

secret_prov_server_epid: src/secret_prov_server.c libs/.mbedtls_libs_copied libs/.epid_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -lsecret_prov_verify_epid -pthread -o $@

# linker option --no-as-needed is required because SGX DCAP library (libsgx_dcap_quoteverify.so)
# does dlopen() instead of directly linking against libsgx_urts.so, and without this option
# compilers remove the "seemingly unused" libsgx_urts.so
secret_prov_server_dcap: src/secret_prov_server.c libs/.mbedtls_libs_copied libs/.dcap_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -Wl,--no-as-needed -lsgx_urts -lsecret_prov_verify_dcap -pthread -o $@

secret_prov_client: src/secret_prov_client.c libs/.mbedtls_libs_copied libs/.common_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -lsecret_prov_attest -o $@

secret_prov_min_client: src/secret_prov_min_client.c libs/.mbedtls_libs_copied libs/.common_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

secret_prov_pf_client: src/secret_prov_pf_client.c libs/.mbedtls_libs_copied libs/.common_libs_copied
	$(CC) $< $(CFLAGS) $(LFLAGS) -o $@

########################### COPIES FOR CONVENIENCE ############################

.SECONDARY: libs/.mbedtls_libs_copied
libs/.mbedtls_libs_copied: mbedtls/.mbedtls_built
	mkdir -p libs

	cd libs                                        && \
	cp ../mbedtls/install/lib/libmbedcrypto.so.* . && \
	ln -s libmbedcrypto.so.* libmbedcrypto.so      && \
	cp ../mbedtls/install/lib/libmbedtls.so.* .    && \
	ln -s libmbedtls.so.* libmbedtls.so            && \
	cp ../mbedtls/install/lib/libmbedx509.so.* .   && \
	ln -s libmbedx509.so.* libmbedx509.so

	touch $@

.SECONDARY: libs/.common_libs_copied
libs/.common_libs_copied:
	mkdir -p libs
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/pf_crypt/pf_crypt pf_crypt
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/common/libsgx_util.so libs/
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_attest.so libs/
	touch $@


.SECONDARY: libs/.epid_libs_copied
libs/.epid_libs_copied: libs/.common_libs_copied
	mkdir -p libs
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_verify_epid.so libs/
	touch $@

.SECONDARY: libs/.dcap_libs_copied
libs/.dcap_libs_copied: libs/.common_libs_copied
	mkdir -p libs
	cp $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/tools/ra-tls/libsecret_prov_verify_dcap.so libs/
	touch $@

############################### CLIENT MANIFEST ###############################

secret_prov_client.manifest: secret_prov_client.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

secret_prov_client.manifest.sgx: secret_prov_client.manifest secret_prov_client libs/.common_libs_copied
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

secret_prov_client.sig: secret_prov_client.manifest.sgx

secret_prov_client.token: secret_prov_client.sig
	graphene-sgx-get-token --output $@ --sig $<

############################# MIN CLIENT MANIFEST #############################

secret_prov_min_client.manifest: secret_prov_min_client.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

secret_prov_min_client.manifest.sgx: secret_prov_min_client.manifest secret_prov_min_client libs/.common_libs_copied
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

secret_prov_min_client.sig: secret_prov_min_client.manifest.sgx

secret_prov_min_client.token: secret_prov_min_client.sig
	graphene-sgx-get-token --output $@ --sig $<

########################## PREPARE PROTECTED FILES ############################

files/input.txt: files/wrap-key files/plain.txt libs/.common_libs_copied
	LD_LIBRARY_PATH=./libs/ ./pf_crypt encrypt -w files/wrap-key -i files/plain.txt -o $@

############################## PF CLIENT MANIFEST #############################

secret_prov_pf_client.manifest: secret_prov_pf_client.manifest.template
	graphene-manifest \
		-Dlog_level=$(GRAPHENE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

secret_prov_pf_client.manifest.sgx: secret_prov_pf_client.manifest secret_prov_pf_client libs/.common_libs_copied
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	graphene-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

secret_prov_pf_client.sig: secret_prov_pf_client.manifest.sgx

secret_prov_pf_client.token: secret_prov_pf_client.sig
	graphene-sgx-get-token --output $@ --sig $<

############################# SGX CHECKS FOR CI ###############################

.PHONY: check_epid
check_epid: app epid files/input.txt
	LD_LIBRARY_PATH=./libs/ ./secret_prov_server_epid >/dev/null & SERVER_ID=$$!; \
	sleep 3; \
	graphene-sgx ./secret_prov_min_client > OUTPUT; \
	graphene-sgx ./secret_prov_client >> OUTPUT; \
	graphene-sgx ./secret_prov_pf_client >> OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep "Received secret = 'ffeeddccbbaa99887766554433221100'" OUTPUT && echo "[ Success 1/4 ]"
	@grep "Received secret1 = 'ffeeddccbbaa99887766554433221100', secret2 = '42'" OUTPUT && echo "[ Success 2/4 ]"
	@grep "\[parent\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 3/4 ]"
	@grep "\[child\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_dcap
check_dcap: app dcap files/input.txt
	LD_LIBRARY_PATH=./libs/ ./secret_prov_server_dcap >/dev/null & SERVER_ID=$$!; \
	sleep 3; \
	graphene-sgx ./secret_prov_min_client > OUTPUT; \
	graphene-sgx ./secret_prov_client >> OUTPUT; \
	graphene-sgx ./secret_prov_pf_client >> OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep "Received secret = 'ffeeddccbbaa99887766554433221100'" OUTPUT && echo "[ Success 1/4 ]"
	@grep "Received secret1 = 'ffeeddccbbaa99887766554433221100', secret2 = '42'" OUTPUT && echo "[ Success 2/4 ]"
	@grep "\[parent\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 3/4 ]"
	@grep "\[child\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 4/4 ]"
	@rm OUTPUT

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest *.so *.so.* OUTPUT pf_crypt \
		secret_prov_server_epid secret_prov_server_dcap \
		secret_prov_client secret_prov_min_client secret_prov_pf_client libs/

.PHONY: distclean
distclean: clean
	$(RM) -r mbedtls/ *.tar.gz files/input.txt
