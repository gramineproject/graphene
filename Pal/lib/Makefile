include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules
include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I. -I../include -I../src -Icrypto/mbedtls/include -I../src/host/$(PAL_HOST)

subdirs = string stdlib network graphene crypto

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
subdirs += crypto/mbedtls/library
crypto_mbedtls_library_objs = $(addsuffix .o, aes aesni asn1parse base64 bignum cipher \
                                              cipher_wrap cmac ctr_drbg dhm entropy gcm md \
                                              md_wrap oid rsa rsa_internal sha256 ssl_tls \
                                              ssl_ciphersuites ssl_cli ssl_srv platform_util)
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
$(addprefix crypto/mbedtls/library/,$(filter-out aes.c,$(patsubst %.o,%.c,$(crypto_mbedtls_library_objs)))): crypto/mbedtls/library/aes.c

string_objs = $(addsuffix .o,atoi memcmp memcpy memset strchr strendswith strlen wordcopy strcmp)
stdlib_objs = $(addsuffix .o,printfmt)
network_objs = $(addsuffix .o,hton inet_pton)
graphene_objs = $(addsuffix .o,config path)
crypto_objs = $(addsuffix .o,udivmodti4)
objs += $(foreach dir,$(subdirs),$(addprefix $(dir)/,$($(subst /,_,$(dir))_objs)))

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
	rm -f $(objs) graphene-lib.a

.PHONY: distclean
distclean: clean
	$(RM) -r crypto/$(MBEDTLS_SRC) crypto/mbedtls
