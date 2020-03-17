include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules
include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I../include/lib -I../include -I../include/pal -I../include/host/$(PAL_HOST) \
          -Icrypto/mbedtls/include -Icrypto/mbedtls/crypto/include

CRYPTO_PROVIDER ?= mbedtls

# Select which crypto adpater you want to use here. This has to match
# the #define in pal_crypto.h.
#
# Unfortunately, we cannot use just one .c file for the adapter. The LibOS
# shim links against the crypto library, but it doesn't use Diffie-Hellman.
# If the Diffie-Hellman stubs are in the same .o file as the SHA1 stubs,
# this pulls Diffie-Hellman code into LibOS shim, resulting in unsatisfied
# symbols.
ifeq ($(CRYPTO_PROVIDER),mbedtls)
crypto_mbedtls_library_objs = \
	crypto/mbedtls/crypto/library/aes.o \
	crypto/mbedtls/crypto/library/aesni.o \
	crypto/mbedtls/crypto/library/base64.o \
	crypto/mbedtls/crypto/library/bignum.o \
	crypto/mbedtls/crypto/library/cipher.o \
	crypto/mbedtls/crypto/library/cipher_wrap.o \
	crypto/mbedtls/crypto/library/cmac.o \
	crypto/mbedtls/crypto/library/ctr_drbg.o \
	crypto/mbedtls/crypto/library/dhm.o \
	crypto/mbedtls/crypto/library/entropy.o \
	crypto/mbedtls/crypto/library/gcm.o \
	crypto/mbedtls/crypto/library/md.o \
	crypto/mbedtls/crypto/library/oid.o \
	crypto/mbedtls/crypto/library/platform_util.o \
	crypto/mbedtls/crypto/library/rsa.o \
	crypto/mbedtls/crypto/library/rsa_internal.o \
	crypto/mbedtls/crypto/library/sha256.o \
	crypto/mbedtls/library/ssl_ciphersuites.o \
	crypto/mbedtls/library/ssl_cli.o \
	crypto/mbedtls/library/ssl_msg.o \
	crypto/mbedtls/library/ssl_srv.o \
	crypto/mbedtls/library/ssl_tls.o

objs += $(crypto_mbedtls_library_objs)
endif

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= https://github.com/ARMmbed/mbed-crypto/archive/
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

crypto/$(MBEDTLS_SRC):
	../../Scripts/download --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) --sha256 $(MBEDTLS_CHECKSUM)

crypto/$(MBEDCRYPTO_SRC):
	../../Scripts/download --output $@ --url $(MBEDCRYPTO_URI)/$(MBEDCRYPTO_SRC) --sha256 $(MBEDCRYPTO_CHECKSUM)

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

# First, build mbedtls library against system's glibc and install in ../install. This library is
# used by, for example, LibOS test cases. Second, prepare mbedtls directory to be used during PAL
# build. A custom config.h header replaces libc dependencies with PAL-specific alternatives.
crypto/mbedtls/CMakeLists.txt: crypto/$(MBEDTLS_SRC) crypto/$(MBEDCRYPTO_SRC)
	cd crypto && tar -mxzf $(MBEDTLS_SRC)
	cd crypto && tar -mxzf $(MBEDCRYPTO_SRC)
	mv crypto/mbedtls-mbedtls-$(MBEDTLS_VERSION) crypto/mbedtls
	$(RM) -r crypto/mbedtls/crypto
	mv crypto/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) crypto/mbedtls
	mv crypto/mbedtls/mbed-crypto-mbedcrypto-3.1.0 crypto/mbedtls/crypto
	mkdir crypto/mbedtls/install
	cd crypto/mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make DESTDIR=install install .
	$(RM) crypto/mbedtls/include/mbedtls/config.h

crypto/mbedtls/include/mbedtls/config.h: crypto/config.h crypto/mbedtls/CMakeLists.txt
	cp crypto/config.h crypto/mbedtls/include/mbedtls

crypto/mbedtls/crypto/library/aes.c: crypto/mbedtls/CMakeLists.txt crypto/mbedtls/include/mbedtls/config.h
$(filter-out crypto/mbedtls/crypto/library/aes.c,$(patsubst %.o,%.c,$(crypto_mbedtls_library_objs))): crypto/mbedtls/crypto/library/aes.c

objs += \
	crypto/udivmodti4.o \
	graphene/config.o \
	graphene/path.o \
	network/hton.o \
	network/inet_pton.o \
	stdlib/printfmt.o \
	string/atoi.o \
	string/memcmp.o \
	string/memcpy.o \
	string/memset.o \
	string/strchr.o \
	string/strcmp.o \
	string/strendswith.o \
	string/strlen.o \
	string/wordcopy.o

$(addprefix $(target),crypto/adapters/mbedtls_adapter.o crypto/adapters/mbedtls_dh.o crypto/adapters/mbedtls_encoding.o): crypto/mbedtls/crypto/library/aes.c

ifeq ($(CRYPTO_PROVIDER),mbedtls)
CFLAGS += -DCRYPTO_USE_MBEDTLS -mrdrnd
objs += crypto/adapters/mbedtls_adapter.o
objs += crypto/adapters/mbedtls_dh.o
objs += crypto/adapters/mbedtls_encoding.o
endif

.PHONY: all
all: $(target)graphene-lib.a

$(target)graphene-lib.a: $(addprefix $(target),$(objs))
	@mkdir -p $(dir $@)
	$(call cmd,ar_a_o)

$(target)%.o: %.c
	@mkdir -p $(dir $@)
	$(call cmd,cc_o_c)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
-include $(patsubst %.o,%.d,$(addprefix $(target),$(objs)))
endif

.PHONY: clean
clean:
	$(RM) $(objs) graphene-lib.a

.PHONY: distclean
distclean: clean
	$(RM) -r crypto/$(MBEDTLS_SRC) crypto/$(MBEDCRYPTO_SRC) crypto/mbedtls
