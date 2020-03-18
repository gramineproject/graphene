include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules
include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I../include/lib -I../include -I../include/pal -Icrypto/mbedtls/include -I../include/host/$(PAL_HOST)

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
	crypto/mbedtls/library/aes.o \
	crypto/mbedtls/library/aesni.o \
	crypto/mbedtls/library/base64.o \
	crypto/mbedtls/library/bignum.o \
	crypto/mbedtls/library/cipher.o \
	crypto/mbedtls/library/cipher_wrap.o \
	crypto/mbedtls/library/cmac.o \
	crypto/mbedtls/library/ctr_drbg.o \
	crypto/mbedtls/library/dhm.o \
	crypto/mbedtls/library/entropy.o \
	crypto/mbedtls/library/gcm.o \
	crypto/mbedtls/library/md.o \
	crypto/mbedtls/library/md_wrap.o \
	crypto/mbedtls/library/oid.o \
	crypto/mbedtls/library/platform_util.o \
	crypto/mbedtls/library/rsa.o \
	crypto/mbedtls/library/rsa_internal.o \
	crypto/mbedtls/library/sha256.o \
	crypto/mbedtls/library/ssl_ciphersuites.o \
	crypto/mbedtls/library/ssl_cli.o \
	crypto/mbedtls/library/ssl_srv.o \
	crypto/mbedtls/library/ssl_tls.o

objs += $(crypto_mbedtls_library_objs)
endif

MBEDTLS_VERSION ?= 2.16.3
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= https://github.com/ARMmbed/mbedtls/archive/
MBEDTLS_CHECKSUM ?= ec72ecf39275327f52b5ee9787271313a0d2960e7342b488d223a118ba164caa

crypto/$(MBEDTLS_SRC):
	../../Scripts/download --output $@ --url $(MBEDTLS_URI)/$(MBEDTLS_SRC) --sha256 $(MBEDTLS_CHECKSUM)

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

# First, build mbedtls library against system's glibc and install in ../install. This library is
# used by, for example, LibOS test cases. Second, prepare mbedtls directory to be used during PAL
# build. A custom config.h header replaces libc dependencies with PAL-specific alternatives.
crypto/mbedtls/CMakeLists.txt: crypto/$(MBEDTLS_SRC)
	cd crypto && tar -mxzf $(MBEDTLS_SRC)
	mv crypto/mbedtls-mbedtls-$(MBEDTLS_VERSION) crypto/mbedtls
	mkdir crypto/mbedtls/install
	cd crypto/mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C && make DESTDIR=install install .
	$(RM) crypto/mbedtls/include/mbedtls/config.h

crypto/mbedtls/include/mbedtls/config.h: crypto/config.h crypto/mbedtls/CMakeLists.txt
	cp crypto/config.h crypto/mbedtls/include/mbedtls

crypto/mbedtls/library/aes.c: crypto/mbedtls/CMakeLists.txt crypto/mbedtls/include/mbedtls/config.h
$(filter-out crypto/mbedtls/library/aes.c,$(patsubst %.o,%.c,$(crypto_mbedtls_library_objs))): crypto/mbedtls/library/aes.c

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

$(addprefix $(target),crypto/adapters/mbedtls_adapter.o crypto/adapters/mbedtls_dh.o crypto/adapters/mbedtls_encoding.o): crypto/mbedtls/library/aes.c

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
	$(RM) -r crypto/$(MBEDTLS_SRC) crypto/mbedtls
