include ../src/Makefile.Host

CC	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
ARFLAGS	=

include ../src/host/$(OS)/Makefile.am

CFLAGS += -I. -I../include -I../src
subdirs = string stdlib network graphene
objs	= $(foreach dir,$(subdirs),$(patsubst %.c,%.o,$(wildcard $(dir)/*.c)))
headers = asm-errlist.h api.h

all: graphene-lib.a

debug: CC = gcc -g
debug: CFLAGS += -DDEBUG
debug: graphene-lib.a

graphene-lib.a: $(objs)
	@echo [ $@ ]
	@$(AR) $(ARFLAGS) $@ $^

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(objs) graphene-lib.a
