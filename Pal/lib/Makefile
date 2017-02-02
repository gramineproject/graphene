include ../src/Makefile.Host

CC	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
ARFLAGS	=

include ../src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -I. -I../include -I../src
subdirs = string stdlib network graphene
objs	= $(foreach dir,$(subdirs),$(patsubst %.c,%.o,$(wildcard $(dir)/*.c)))
headers = asm-errlist.h api.h

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
