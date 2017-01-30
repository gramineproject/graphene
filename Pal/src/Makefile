export PAL_DIR = $(CURDIR)
export RUNTIME_DIR = $(CURDIR)/../../Runtime

include Makefile.Host
-include Makefile.Status

ifeq ($(DEBUG),1)
BUILD_TARGET = $(OS)-debug
else
BUILD_TARGET = $(OS)
endif

# Customizable PAL Targets
# (specify in Makefile.am in host-specific directories)
pal_loader =
pal_sec =
pal_lib =
pal_lib_deps =
pal_lib_post =
pal_static =

include host/$(OS)/Makefile.am

CFLAGS	+= -I. -I../include -Ihost/$(OS) -I../lib

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

files_to_build = $(pal_lib) $(pal_lib_post) $(pal_static) \
		 $(pal_loader) $(pal_sec)

defs	= -DIN_PAL -D$(OS_MACRO) -DPAL_DIR=$(PAL_DIR) \
	  -DRUNTIME_DIR=$(RUNTIME_DIR)
objs	= $(addprefix db_,streams memory threading semaphore events process \
	    object main misc ipc exception rtld) slab printf
graphene_lib = .lib/graphene-lib.a
host_lib = host/$(OS)/libpal-$(OS).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h) host/$(OS)/pal_host.h

ifeq ($(SYS),x86_64-linux-gnu)
files_to_build += user_start.o user_shared_start.o
endif

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
endif
export DEBUG

runtime_loader = $(RUNTIME_DIR)/pal-$(OS)

ifneq ($(pal_lib),)
	runtime_lib += $(RUNTIME_DIR)/libpal-$(OS)$(suffix $(pal_lib))
endif

ifneq ($(pal_sec),)
	runtime_sec += $(RUNTIME_DIR)/pal_sec-$(OS)
endif

files_to_install = $(runtime_loader) $(runtime_lib) $(runtime_sec)

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

host_endian.h: host/$(OS)/host_endian.h
	ln -sf $< $@

$(host_lib): $(graphene_lib)
	@[ ! -d host/$(OS) ] || $(MAKE) -C host/$(OS)

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
	@[ ! -d security/$(OS) ] || $(MAKE) -C security/$(OS)

$(runtime_sec): $(pal_sec)
	cp -f $< $@
endif

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
	rm -rf $(addsuffix .o,$(objs)) $(files_to_build) host_endian.h .lib Makefile.Status
	@[ ! -d host/$(OS) ] || $(MAKE) -C host/$(OS) clean
	@[ ! -d security/$(OS) ] || $(MAKE) -C security/$(OS) clean
