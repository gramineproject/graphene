MAKEFLAGS += --check-symlink-times

include Makefile.Host

CC	= gcc
AR	= ar rcs
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
LDFLAGS	= -shared -nostdlib -z combreloc -z defs
ARFLAGS	=

pal_loader = libpal.so
pal_sec =
pal_lib = libpal.so
pal_lib_deps =
pal_lib_post =
pal_static = libpal.a

include host/$(OS)/Makefile.am

CFLAGS	+= -I. -I../include -Ihost/$(OS) -I../lib

pal_target = $(pal_lib) $(pal_lib_post) $(pal_static) $(pal_loader) $(pal_sec) pal pal_sec
defs	= -DIN_PAL -DSRCDIR="$(PWD)/"
objs	= $(addprefix db_,streams memory threading semaphore events process \
	    object main misc ipc exception rtld) slab printf
graphene_lib = ../lib/graphene-lib.a
host_lib = host/$(OS)/libpal-$(OS).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h)

all: $(pal_target)

debug: debug = debug
debug: CC = gcc -gdwarf-2 -g3
debug: CFLAGS += -DDEBUG
debug: $(pal_target)

.PHONY: $(host_lib) $(graphene_lib)

$(graphene_lib):
	make -C ../lib $(debug)

$(host_lib):
	@[ ! -d host/$(OS) ] || make -C host/$(OS) $(debug)

ifneq ($(pal_sec),)
$(pal_sec):
	@[ ! -d security/$(OS) ] || make -C security/$(OS) $(debug)

pal_sec: $(pal_sec)
	ln -sf $(pal_sec) pal_sec
endif

$(pal_lib): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib) $(pal_lib_deps)
	@echo [ libpal.exe ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) $(LDFLAGS-suffix)

pal: $(pal_loader)
	ln -sf $(pal_loader) pal

ifneq ($(pal_lib_post),)
$(pal_lib_post): $(pal_lib)
	make -C host/$(OS) ../../$@
endif

$(pal_static): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib)
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
