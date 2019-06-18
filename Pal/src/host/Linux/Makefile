include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../lib \
	   -I../../../ipc/linux \
	   -I../../../linux-kernel/graphene
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

host_files = libpal-Linux.a

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception) manifest clone-x86_64 gettimeofday-x86_64
graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG -Wsign-compare
export DEBUG
endif

libpal-Linux.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ host/Linux/$@ ]
	@$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	@echo [ host/Linux/$@ ]
	@$(CC) -MD -MP $(CFLAGS) $(defs) -c $< -o $@

%.o: %.S
	@echo [ host/Linux/$@ ]
	@$(AS) -MD -MP $(ASFLAGS) $(defs) -c $< -o $@

-include $(addsuffix .d,$(objs))

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(addsuffix .d,$(objs)) $(host_files) $(CLEAN_FILES)

.PHONY: test
test:
