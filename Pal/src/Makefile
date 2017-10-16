export PAL_DIR = $(CURDIR)
export RUNTIME_DIR = $(CURDIR)/../../Runtime
$(info Saved Target is $(SAVED_TARGET))
include Makefile.Host
-include Makefile.Status
$(info Saved Target is $(SAVED_TARGET))
ifeq ($(DEBUG),1)
BUILD_TARGET = $(PAL_HOST)-debug
else
BUILD_TARGET = $(PAL_HOST)
endif

# Customizable PAL Targets
# (specify in Makefile.am in host-specific directories)
pal_loader =
pal_sec =
pal_lib =
pal_lib_deps =
pal_lib_post =
pal_static =
pal_gdb =
include host/$(PAL_HOST)/Makefile.am

CFLAGS	+= -I. -I../include -Ihost/$(PAL_HOST) -I../lib

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

files_to_build = $(pal_lib) $(pal_lib_post) $(pal_static) \
		 $(pal_loader) $(pal_sec)

defs	= -DIN_PAL -D$(PAL_HOST_MACRO) -DPAL_DIR=$(PAL_DIR) \
	  -DRUNTIME_DIR=$(RUNTIME_DIR)
objs	= $(addprefix db_,streams memory threading semaphore events process \
	    object main misc ipc exception rtld) slab printf
graphene_lib = .lib/graphene-lib.a
host_lib = host/$(PAL_HOST)/libpal-$(PAL_HOST).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h) host/$(PAL_HOST)/pal_host.h

ifeq ($(SYS),x86_64-linux-gnu)
files_to_build += user_start.o user_shared_start.o
endif

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
endif
export DEBUG

runtime_loader = $(RUNTIME_DIR)/pal-$(PAL_HOST)

ifneq ($(pal_lib),)
	runtime_lib += $(RUNTIME_DIR)/libpal-$(PAL_HOST)$(suffix $(pal_lib))
endif

ifneq ($(pal_sec),)
	runtime_sec += $(RUNTIME_DIR)/pal_sec-$(PAL_HOST)
endif

ifneq ($(pal_gdb),)
	runtime_gdb += $(RUNTIME_DIR)/pal_gdb-$(PAL_HOST)
endif

files_to_install = $(runtime_loader) $(runtime_lib) $(runtime_sec) $(runtime_gdb)

all: | check_target $(files_to_build) $(files_to_install)

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

host_endian.h: host/$(PAL_HOST)/host_endian.h
	ln -sf $< $@

$(host_lib): $(graphene_lib)
	@[ ! -d host/$(PAL_HOST) ] || $(MAKE) -C host/$(PAL_HOST)

$(pal_loader) $(pal_sec): $(host_lib)

$(runtime_loader): $(pal_loader)
	cp -f $< $@

ifneq ($(pal_lib),)
$(pal_lib): $(addsuffix .o,$(objs)) $(host_lib) $(graphene_lib) $(pal_lib_deps)
	@echo [ $@ ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) $(LDFLAGS-suffix)

$(runtime_lib): $(pal_lib)
	cp -f $< $@
endif

ifneq ($(pal_sec),)
$(pal_sec): $(graphene_lib)
	@[ ! -d security/$(PAL_HOST) ] || $(MAKE) -C security/$(PAL_HOST)

$(runtime_sec): $(pal_sec)
	cp -f $< $@
endif

ifneq ($(pal_gdb),)
$(runtime_gdb): $(pal_gdb)
ifeq ($(abspath $(pal_gdb)),$(pal_gdb))
	ln -sf $< $@
else
	ln -sf ../Pal/src/$< $@
endif
endif

ifneq ($(pal_lib_post),)
$(pal_lib_post): $(pal_lib)
	$(MAKE) -C host/$(PAL_HOST) ../../$@
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
ifneq ($(SAVED_OS),$(PAL_HOST))
	$(MAKE) clean PAL_HOST=$(SAVED_OS)
endif
	rm -rf $(addsuffix .o,$(objs)) $(files_to_build) host_endian.h .lib Makefile.Status
	@[ ! -d host/$(PAL_HOST) ] || $(MAKE) -C host/$(PAL_HOST) clean
	@[ ! -d security/$(PAL_HOST) ] || $(MAKE) -C security/$(PAL_HOST) clean
