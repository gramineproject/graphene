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

CJSON_VERSION ?= 1.7.12
CJSON_SRC ?= v$(CJSON_VERSION).tar.gz
CJSON_URI ?= https://github.com/DaveGamble/cJSON/archive/
CJSON_CHECKSUM ?= 760687665ab41a5cff9c40b1053c19572bcdaadef1194e5cba1b5e6f824686e7
DOWNLOAD_SCRIPT := ../../../../../../Scripts/download

cJSON.c cJSON.h:
	$(DOWNLOAD_SCRIPT) --output $(CJSON_SRC) --url $(CJSON_URI)/$(CJSON_SRC) --sha256 $(CJSON_CHECKSUM)
	tar -mxzf $(CJSON_SRC)
	cp cJSON-$(CJSON_VERSION)/cJSON.c .
	cp cJSON-$(CJSON_VERSION)/cJSON.h .

attestation.o: cJSON.h

libsgx_util.so: attestation.o cJSON.o ias.o util.o
	$(CC) $^ $(LDFLAGS) ../../.lib/crypto/adapters/mbedtls_encoding.o -lmbedcrypto -lcurl -shared -o $@

.PHONY: install
install:
	install libsgx_util.so ${PREFIX}/lib
	install ../../../../../lib/crypto/mbedtls/install/lib/libmbedcrypto.so ${PREFIX}/lib
	ldconfig

.PHONY: clean
clean:
	$(RM) *.gz *.o *.so

.PHONY: distclean
distclean: clean
	$(RM) -r cJSON-$(CJSON_VERSION) cJSON.c cJSON.h
