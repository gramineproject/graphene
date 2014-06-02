MAKEFLAGS += --check-symlink-times

include Makefile.Host

CC	= gcc
AR	= ar rcs
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin \
	  -I. -I../include -Ihost/$(OS) -I../lib
LDFLAGS	= -shared -nostdlib --version-script pal.map -z combreloc -z defs \
	  -T pal.lds
ARFLAGS	=

pal_target = libpal.a libpal.so

include host/$(OS)/Makefile.am

defs	= -DIN_PAL -DSRCDIR="$(PWD)/"
objs	= $(addprefix db_,streams memory threading semaphore events process \
	    object main misc ipc exception rtld) slab printf
graphene_lib = ../lib/graphene-lib.a
host_lib = host/$(OS)/libpal-$(OS).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h)

all: $(pal_target) security

debug: debug = debug
debug: CC = gcc -gdwarf-2 -g3
debug: CFLAGS += -DDEBUG
debug: $(pal_target) security

.PHONY: security $(host_lib) $(graphene_lib)

$(graphene_lib):
	make -C ../lib $(debug)

$(host_lib):
	@[ ! -d host/$(OS) ] || make -C host/$(OS) $(debug)

security:
	@[ ! -d security/$(OS) ] || make -C security/$(OS) $(debug)

libpal.so: $(addsuffix .o,$(objs)) $(filter %.map %.lds,$(LDFLAGS)) \
	   $(host_lib) $(graphene_lib)
	@echo [ $@ ]
	@[ ! -f $@ ] || mv -f $@ $@.backup
	@$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) -soname=$@

libpal.a: $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib)
	@echo [ $@ ]
	@[ ! -f $@ ] || mv -f $@ $@.backup
	@$(AR) $(ARFLAGS) $@ $^

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.e: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@

clean:
	rm -rf $(addsuffix .o,$(objs))
	for f in $(pal_target); \
	do \
		[ ! -f $$f ] || mv -f $$f $$f.backup || true; \
	done
	@[ ! -d host/$(OS) ] || make -C host/$(OS) clean
	@[ ! -d security/$(OS) ] || make -C security/$(OS) clean
