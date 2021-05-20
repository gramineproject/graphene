include ../../../../../../Scripts/Makefile.configs

CFLAGS += -I../.. \
          -I../common \
          -I../../../../../../common/src/crypto/mbedtls/install/include \
          -fPIC -fvisibility=hidden

LDFLAGS += -L../../../../../../common/src/crypto/mbedtls/install/lib -Wl,-rpath,.

.PHONY: all
all: epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: epid
epid: libra_tls_attest.so libra_tls_verify_epid.so \
      libsecret_prov_attest.so libsecret_prov_verify_epid.so

.PHONY: dcap
dcap: libra_tls_attest.so libra_tls_verify_dcap.so libra_tls_verify_dcap_graphene.so \
      libsecret_prov_attest.so libsecret_prov_verify_dcap.so

libra_tls_attest.so: ra_tls_attest.o
	$(CC) $^ $(LDFLAGS) -l:libmbedx509.a -l:libmbedcrypto.a -shared -o $@

libra_tls_verify_epid.so: ra_tls_verify_common.o ra_tls_verify_epid.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -shared -o $@

libra_tls_verify_dcap.so: ra_tls_verify_common.o ra_tls_verify_dcap.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -lsgx_dcap_quoteverify -shared -o $@

libra_tls_verify_dcap_graphene.so: ra_tls_verify_common.o ra_tls_verify_dcap.o ra_tls_verify_dcap_urts.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -lsgx_dcap_quoteverify -shared -o $@

libsecret_prov_attest.so: ra_tls_attest.o secret_prov_common.o secret_prov_attest.o
	$(CC) $^ $(LDFLAGS) -l:libmbedx509.a -l:libmbedtls.a -l:libmbedcrypto.a -shared -o $@

libsecret_prov_verify_epid.so: ra_tls_verify_common.o ra_tls_verify_epid.o secret_prov_common.o secret_prov_verify.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -lmbedtls -shared -o $@

libsecret_prov_verify_dcap.so: ra_tls_verify_common.o ra_tls_verify_dcap.o secret_prov_common.o secret_prov_verify.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -lmbedtls -lsgx_dcap_quoteverify -shared -o $@

.PHONY: clean
clean:
	$(RM) *.o *.so

.PHONY: distclean
distclean: clean

.PHONY: install
install: ;
