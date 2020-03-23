include ../../../../../../Scripts/Makefile.configs

CFLAGS += -I../.. \
          -I../../../../../include/lib \
          -I../../../../../lib/crypto/mbedtls/install/include \
          -DCRYPTO_USE_MBEDTLS \
          -D_POSIX_C_SOURCE=200809L \
          -fPIC

LDFLAGS += -L../../../../../lib/crypto/mbedtls/install/lib

PREFIX ?= /usr/local

.PHONY: all
all: libsgx_util.so

libsgx_util.so: ias.o util.o
	$(CC) $^ $(LDFLAGS) ../../.lib/crypto/adapters/mbedtls_encoding.o -lmbedcrypto -lcurl -shared -o $@

.PHONY: install
install:
	install libsgx_util.so ${PREFIX}/lib
	install ../../../../../lib/crypto/mbedtls/install/lib/libmbedcrypto.so ${PREFIX}/lib
	ldconfig

.PHONY: clean
clean:
	$(RM) *.o *.so
