include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules
include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I. -I../include -I../src -I../src/host/$(PAL_HOST)

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
subdirs += crypto/mbedtls
crypto_mbedtls_objs = $(addsuffix .o,aes aesni asn1parse base64 bignum cipher cipher_wrap cmac dhm md md_wrap oid rsa sha256)
endif

string_objs = $(addsuffix .o,atoi memcmp memcpy memset strchr strendswith strlen wordcopy)
stdlib_objs = $(addsuffix .o,printfmt)
network_objs = $(addsuffix .o,hton inet_pton)
graphene_objs = $(addsuffix .o,config path)
crypto_objs = $(addsuffix .o,udivmodti4)
objs += $(foreach dir,$(subdirs),$(addprefix $(dir)/,$($(subst /,_,$(dir))_objs)))

ifeq ($(CRYPTO_PROVIDER),mbedtls)
CFLAGS += -DCRYPTO_USE_MBEDTLS
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

ifeq ($(filter clean,$(MAKECMDGOALS)),)
-include $(patsubst %.o,%.d,$(addprefix $(target),$(objs)))
endif

.PHONY: clean
clean:
	rm -f $(objs) graphene-lib.a
