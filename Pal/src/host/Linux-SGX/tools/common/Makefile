include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

# IN_PAL is defined on 18.04 Jenkins pipeline for some reason, override it since we're NOT in PAL
CFLAGS := $(filter-out -DIN_PAL, $(CFLAGS))
CFLAGS += -iquote ../.. \
          -iquote ../../../../../../common/include \
          -iquote ../../../../../../common/include/arch/$(ARCH) \
          -iquote ../../protected-files \
          -I../../../../../../common/src/crypto/mbedtls/install/include \
          -DCRYPTO_USE_MBEDTLS \
          -D_POSIX_C_SOURCE=200809L \
          -fPIC

LDFLAGS += -L../../../../../../common/src/crypto/mbedtls/install/lib

DEFAULT_PREFIX := /usr/local
PREFIX ?= $(DEFAULT_PREFIX)

.PHONY: all
all: libsgx_util.so

CJSON_VERSION ?= 1.7.12
CJSON_SRC ?= v$(CJSON_VERSION).tar.gz
CJSON_URI ?= \
	https://github.com/DaveGamble/cJSON/archive/$(CJSON_SRC) \
	https://packages.grapheneproject.io/distfiles/cJSON-$(CJSON_VERSION).tar.gz
CJSON_CHECKSUM ?= 760687665ab41a5cff9c40b1053c19572bcdaadef1194e5cba1b5e6f824686e7
DOWNLOAD_SCRIPT := ../../../../../../Scripts/download

$(CJSON_SRC):
	$(DOWNLOAD_SCRIPT) --output $(CJSON_SRC) --sha256 $(CJSON_CHECKSUM) \
		$(foreach mirror,$(CJSON_URI),--url $(mirror))

cJSON-$(CJSON_VERSION):
	mkdir -p $@

cJSON-$(CJSON_VERSION)/cJSON.h cJSON-$(CJSON_VERSION)/cJSON.c: $(CJSON_SRC) | cJSON-$(CJSON_VERSION)
	tar --touch -zxvf $^ $@

cJSON.c cJSON.h: %: cJSON-$(CJSON_VERSION)/%
	cp cJSON-$(CJSON_VERSION)/$@ .

attestation.o: cJSON.h

protected_files.o: ../../protected-files/protected_files.c
	$(call cmd,cc_o_c)

lru_cache.o: ../../protected-files/lru_cache.c
	$(call cmd,cc_o_c)

cJSON.o: cJSON.c cJSON.h

libsgx_util.so: attestation.o cJSON.o ias.o lru_cache.o pf_util.o protected_files.o util.o
	$(CC) $^ $(LDFLAGS) -lmbedcrypto -lcurl -shared -o $@

.PHONY: install
install:
	install -D libsgx_util.so -t ${PREFIX}/lib
	install -D ../../../../../../common/src/crypto/mbedtls/install/lib/libmbedcrypto.so -t ${PREFIX}/lib
ifeq ($(PREFIX), $(DEFAULT_PREFIX))
	ldconfig
else
	ldconfig -n ${PREFIX}/lib
endif

.PHONY: clean
clean:
	$(RM) *.d *.gz *.o *.so

.PHONY: distclean
distclean: clean
	$(RM) -r cJSON-$(CJSON_VERSION) cJSON.c cJSON.h
