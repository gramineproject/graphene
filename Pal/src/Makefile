export PAL_DIR = $(CURDIR)
export RUNTIME_DIR = $(CURDIR)/../../Runtime

include Makefile.Host

# Customizable PAL Targets
# (specify in Makefile.am in host-specific directories)
# For concurrent builds, all PAL targets must be in host-specific directories
pal_loader =
pal_sec =
pal_lib =
pal_lib_deps =
pal_lib_post =
pal_static =
pal_gdb =

include host/$(PAL_HOST)/Makefile.am

HOST_DIR = host/$(PAL_HOST)
LIB_DIR = $(HOST_DIR)/.lib
OBJ_DIR = $(HOST_DIR)/.obj

CFLAGS	+= -I. -I../include -I$(HOST_DIR) -I../lib

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

# Build Targets:
#     (1) Host-specific targets are in "host/{Host Name}".
#     (2) Generic targets are in "host/{Host Name}/.obj".
#     (3) API library targets are in "host/{Host Name}/.lib".

files_to_build = $(pal_lib) $(pal_lib_post) $(pal_static) \
		 $(pal_loader) $(pal_sec)

defs	= -DIN_PAL -DHOST_TYPE="$(PAL_HOST)" -D$(PAL_HOST_MACRO) -DPAL_DIR=$(PAL_DIR) \
	  -DRUNTIME_DIR=$(RUNTIME_DIR)
objs	= $(addprefix db_,streams memory threading mutex events process \
	    object main misc ipc exception rtld) slab printf

graphene_lib = $(LIB_DIR)/graphene-lib.a
host_lib = $(HOST_DIR)/libpal-$(PAL_HOST).a
headers	= $(wildcard *.h) $(wildcard ../lib/*.h) $(HOST_DIR)/pal_host.h

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
files_to_build += user_start.o user_shared_start.o
endif

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
endif
export DEBUG

# Install Targets (all in RUNTIME_DIR):
#       pal-{Host Name}:       loader for PAL (as an executable)
#       libpal-{Host Name}.so: dynamic-linking library
#       pal_sec-{Host Name}:   secure loader for PAL (as an executable)
#       pal_gdb-{Host Name}:   debugger for PAL (as an executable)

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


###########################
##  Generic Build Rules  ##
###########################

.PHONY: all
all: $(files_to_build) $(files_to_install)

$(LIB_DIR)/host_endian.h: $(HOST_DIR)/host_endian.h
	@mkdir -p $(LIB_DIR)
	cp -f $< $@

.PHONY: $(host_lib) $(graphene_lib) $(pal_lib) $(pal_sec)

$(graphene_lib): $(LIB_DIR)/host_endian.h
	$(MAKE) -C ../lib target=$(abspath $(LIB_DIR))/

$(host_lib): $(graphene_lib)
	@[ ! -d host/$(PAL_HOST) ] || $(MAKE) -C host/$(PAL_HOST)

$(pal_loader) $(pal_sec): $(host_lib)

$(runtime_loader): $(pal_loader)
	cp -f $< $@

ifneq ($(pal_lib),)
$(pal_lib): $(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(objs))) \
	    $(host_lib) $(graphene_lib) $(pal_lib_deps)
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
	@$(MAKE) -C $(HOST_DIR) $@
endif

$(pal_static): $(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(objs))) \
	       $(host_lib) $(graphene_lib)
	@echo [ $@ ]
	@$(AR) $(ARFLAGS) $@ $^ $(ARFLAGS-suffix)

$(OBJ_DIR)/%.asm: %.c $(headers)
	@mkdir -p $(OBJ_DIR)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

user_start.o: user_start.S
	@echo [ $@ ]
	@$(CC) -c $< -o $@

user_shared_start.o: user_start.S
	@echo [ $@ ]
	@$(CC) -DSHARED -fPIC -c $< -o $@

$(OBJ_DIR)/%.o: %.c $(headers)
	@mkdir -p $(OBJ_DIR)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@ $(CFLAGS-suffix)

$(OBJ_DIR)/%.e: %.c $(headers)
	@mkdir -p $(OBJ_DIR)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@ $(CFLAGS-suffix)

.PHONY: clean
clean:
	rm -rf $(LIB_DIR) $(OBJ_DIR)
	@[ ! -d $(HOST_DIR) ] || $(MAKE) -C $(HOST_DIR) clean
	@[ ! -d security/$(PAL_HOST) ] || $(MAKE) -C security/$(PAL_HOST) clean
