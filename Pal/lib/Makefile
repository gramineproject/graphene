include ../src/Makefile.Host

CC	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
ARFLAGS	=

include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I. -I../include -I../src

# Include host_endian.h from either the host-specific directory,
# or directly under the target directory.
ifeq ($(target),)
CFLAGS += -I../src/host/$(PAL_HOST)
else
CFLAGS += -I$(target)
endif

subdirs = string stdlib network graphene util crypto
headers = api.h pal_crypto.h

# Choose Crypto provider among (mbedtls|wolfssl)
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
headers += $(wildcard crypto/mbedtls/mbedtls/*.h)
endif
ifeq ($(CRYPTO_PROVIDER),wolfssl)
subdirs += crypto/wolfssl
headers += $(wildcard crypto/wolfssl/*.h)
endif

objs	= $(foreach dir,$(subdirs),$(patsubst %.c,%.o,$(wildcard $(dir)/*.c)))

ifeq ($(CRYPTO_PROVIDER),mbedtls)
CFLAGS += -DCRYPTO_USE_MBEDTLS
objs += crypto/adapters/mbedtls_adapter.o
objs += crypto/adapters/mbedtls_dh.o
endif
ifeq ($(CRYPTO_PROVIDER),wolfssl)
CFLAGS += -DCRYPTO_USE_WOLFSSL
objs += crypto/adapters/wolfssl_adapter.o
objs += crypto/adapters/wolfssl_dh.o
endif

.PHONY: all
all: $(target)graphene-lib.a

ifeq ($(DEBUG),1)
CC += -g
CFLAGS += -DDEBUG
endif

$(target)graphene-lib.a: $(addprefix $(target),$(objs))
	@echo [ $(notdir $@) ]
	@mkdir -p $(dir $@)
	@$(AR) $(ARFLAGS) $@ $^

$(target)%.o: %.c $(headers)
	@echo [ $(notdir $@) ]
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(objs) graphene-lib.a
