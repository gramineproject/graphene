include ../../../../../../Scripts/Makefile.configs

CFLAGS += -I../.. \
          -I../common \
          -I../../../../../lib/crypto/mbedtls/install/include \
          -I../../../../../lib/crypto/mbedtls/crypto/include \
          -fPIC

LDFLAGS += -L../../../../../lib/crypto/mbedtls/install/lib -Wl,-rpath,.

.PHONY: all
all: libra_tls_verify.so libra_tls_attest.so

libra_tls_verify.so: ra_tls_verify.o
	$(CC) $^ $(LDFLAGS) -L../common -lsgx_util -lmbedcrypto -lmbedx509 -shared -o $@

libra_tls_attest.so: ra_tls_attest.o
	$(CC) $^ $(LDFLAGS) -l:libmbedcrypto.a -l:libmbedx509.a -shared -o $@

.PHONY: clean
clean:
	$(RM) *.o *.so

.PHONY: distclean
distclean: clean
