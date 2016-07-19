include Makefile.Host
-include Makefile.Status

CC	= gcc
AR	= ar rcs
LD	= ld

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin
LDFLAGS	= -shared -nostdlib -z combreloc -z defs
ARFLAGS	=

export PAL_DIR = $(shell pwd)

pal_loader = libpal.so
pal_sec =
pal_lib = libpal.so
pal_lib_deps =
pal_lib_post =
pal_static = libpal.a

include host/$(OS)/Makefile.am

CFLAGS	+= -I. -I../include -Ihost/$(OS) -I../lib

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

pal_target = $(pal_lib) $(pal_lib_post) $(pal_static) $(pal_loader) $(pal_sec) pal
defs	= -DIN_PAL -D$(OS_MACRO) -DPAL_DIR="$(PAL_DIR)"
objs	= $(addprefix db_,streams memory threading semaphore events process \
	    object main misc ipc exception rtld) slab printf
graphene_lib = .lib/graphene-lib.a
host_lib = host/$(OS)/libpal-$(OS).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h) host/$(OS)/pal_host.h

ifneq ($(pal_sec),)
pal_target += pal_sec
endif

ifeq ($(SYS),x86_64-linux-gnu)
pal_target += user_start.o user_shared_start.o
endif

all: | check_target $(pal_target)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
endif
export DEBUG

ifeq ($(DEBUG),1)
BUILD_TARGET = $(OS)-debug
else
BUILD_TARGET = $(OS)
endif

ifndef SAVED_TARGET
SAVED_TARGET = $(BUILD_TARGET)
endif

SAVED_OS = $(patsubst %-debug,%,$(SAVED_TARGET))

.PHONY: check_target
check_target:
	@echo "Building target: $(BUILD_TARGET)"
ifneq ($(SAVED_TARGET),$(BUILD_TARGET))
	$(error "A different target is built earlier. Prune the directory first.")
endif
	@echo "SAVED_TARGET = $(BUILD_TARGET)" > Makefile.Status

.PHONY: $(host_lib) $(graphene_lib) $(pal_lib) $(pal_sec)

$(graphene_lib): host_endian.h
	$(MAKE) -C ../lib target=$(shell pwd)/.lib/

host_endian.h: host/$(OS)/host_endian.h
	ln -sf $< $@

$(host_lib): $(graphene_lib)
	@[ ! -d host/$(OS) ] || $(MAKE) -C host/$(OS)

ifneq ($(pal_sec),)
$(pal_sec): $(graphene_lib)
	@[ ! -d security/$(OS) ] || $(MAKE) -C security/$(OS)

pal_sec: $(pal_sec)
	ln -sf $(pal_sec) pal_sec
endif

$(pal_lib): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib) $(pal_lib_deps)
	@echo [ $@ ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) $(LDFLAGS-suffix)

pal: $(pal_loader)
	ln -sf $(pal_loader) pal

ifneq ($(pal_lib_post),)
$(pal_lib_post): $(pal_lib)
	$(MAKE) -C host/$(OS) ../../$@
endif

$(pal_static): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib)
	@echo [ $@ ]
	$(AR) $(ARFLAGS) $@ $^ $(ARFLAGS-suffix)

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

user_start.o: user_start.S
	@echo [ $@ ]
	@$(CC) -c $< -o $@

user_shared_start.o: user_start.S
	@echo [ $@ ]
	@$(CC) -DSHARED -fPIC -c $< -o $@

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@ $(CFLAGS-suffix)

%.e: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@ $(CFLAGS-suffix)

clean:
ifneq ($(SAVED_OS),$(OS))
	$(MAKE) clean OS=$(SAVED_OS)
endif
	rm -rf $(addsuffix .o,$(objs)) $(pal_target) host_endian.h .lib Makefile.Status
	@[ ! -d host/$(OS) ] || $(MAKE) -C host/$(OS) clean
	@[ ! -d security/$(OS) ] || $(MAKE) -C security/$(OS) clean

