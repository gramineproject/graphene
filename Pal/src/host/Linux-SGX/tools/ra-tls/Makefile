include ../../../../../../Scripts/Makefile.configs

CFLAGS += -I../.. \
          -I../common \
          -I../../../../../lib/crypto/mbedtls/install/include \
          -I../../../../../lib/crypto/mbedtls/crypto/include \
          -fPIC -fvisibility=hidden

LDFLAGS += -L../../../../../lib/crypto/mbedtls/install/lib -Wl,-rpath,.

.PHONY: all
all: epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: epid
epid: libra_tls_attest.so libra_tls_verify_epid.so

.PHONY: dcap
dcap: libra_tls_attest.so libra_tls_verify_dcap.so

libra_tls_attest.so: ra_tls_attest.o
	$(CC) $^ $(LDFLAGS) -l:libmbedx509.a -l:libmbedcrypto.a -shared -o $@

libra_tls_verify_epid.so: ra_tls_verify_common.o ra_tls_verify_epid.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -shared -o $@

libra_tls_verify_dcap.so: ra_tls_verify_common.o ra_tls_verify_dcap.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -lsgx_dcap_quoteverify -shared -o $@

.PHONY: clean
clean:
	$(RM) *.o *.so

.PHONY: distclean
distclean: clean
