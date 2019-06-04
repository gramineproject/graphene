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
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception) manifest clone-x86_64 gettimeofday-x86_64
graphene_lib = .lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG -Wsign-compare
export DEBUG
endif

libpal-Linux.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	$(call cmd,ar_a_o)

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	$(call cmd,cc_o_c)

%.e %.i: %.c $(headers)
	$(call cmd,cpp_i_c)

%.s: %.c $(headers)
	$(call cmd,cc_s_c)

%.o: %.S $(headers)
	$(call cmd,as_o_S)

%.e %.s: %.S $(headers)
	$(call cmd,cpp_s_S)

include ../../../../Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files) $(CLEAN_FILES)
