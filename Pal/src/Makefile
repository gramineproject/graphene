MAKEFLAGS += --check-symlink-times

include Makefile.Host

CC	= gcc
AR	= ar rcs
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
LDFLAGS	= -shared -nostdlib --version-script pal.map -z combreloc -z defs \
	  -T pal.lds
ARFLAGS	=

pal_loader = libpal.so
pal_lib = libpal.a

include host/$(OS)/Makefile.am

CFLAGS	+= -I. -I../include -Ihost/$(OS) -I../lib

pal_target = $(pal_loader) $(pal_lib)
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

$(pal_loader): $(addsuffix .o,$(objs)) $(filter %.map %.lds,$(LDFLAGS)) \
	    $(host_lib) $(graphene_lib)
	@echo [ libpal.exe ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) $(LDFLAGS-suffix)

$(pal_lib): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib)
	@echo [ $@ ]
	$(AR) $(ARFLAGS) $@ $^ $(ARFLAGS-suffix)

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@ $(CFLAGS-suffix)

%.e: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@ $(CFLAGS-suffix)

clean:
	rm -rf $(addsuffix .o,$(objs)) $(pal_target)
	@[ ! -d host/$(OS) ] || make -C host/$(OS) clean
	@[ ! -d security/$(OS) ] || make -C security/$(OS) clean
