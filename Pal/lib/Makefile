include ../src/Makefile.Host

CC	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
ARFLAGS	=

include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I. -I../include -I../src
subdirs = string stdlib network graphene util crypto
headers = api.h

# Select which crypto adpater you want to use here. This has to match
# the #define in pal_crypto.h.
subdirs += crypto/mbedtls
#subdirs += crypto/wolfssl
objs	= $(foreach dir,$(subdirs),$(patsubst %.c,%.o,$(wildcard $(dir)/*.c)))
objs += crypto/adapters/mbedtls_adapter.o
#objs += crypto/adapters/wolfssl_adapter.o

all: $(target)graphene-lib.a

ifeq ($(DEBUG),1)
CC += -g
CFLAGS += -DDEBUG
endif

$(target)graphene-lib.a: $(addprefix $(target),$(objs))
	@echo [ $(notdir $@) ]
	@mkdir -p $(dir $@)
	@$(AR) $(ARFLAGS) $@ $^

../src/host_endian.h:
	@$(MAKE) -C ../src host_endian.h

$(target)%.o: %.c $(headers) ../src/host_endian.h
	@echo [ $(notdir $@) ]
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(objs) graphene-lib.a
