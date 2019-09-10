include ../../../../Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../include/pal \
	   -I../../../include/host/Linux -I../../../lib \
	   -I../../../ipc/linux \
	   -I../../../linux-kernel/graphene
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

host_files = libpal-Linux.a pal.map

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception) clone-x86_64 gettimeofday-x86_64
graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: $(host_files)

libpal-Linux.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	$(call cmd,ar_a_o)

%.o: %.c
	$(call cmd,cc_o_c)

%.i: %.c
	$(call cmd,cpp_i_c)

%.s: %.c
	$(call cmd,cc_s_c)

%.o: %.S
	$(call cmd,as_o_S)

%.s: %.S
	$(call cmd,cpp_s_S)

include ../../../../Makefile.rules

-include $(addsuffix .d,$(objs)) $(addsuffix .i.d,$(objs)) $(addsuffix .s.d,$(objs))

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files) $(CLEAN_FILES) \
	      $(addsuffix .d,$(objs)) $(addsuffix .i.d,$(objs)) \
	      $(addsuffix .s.d,$(objs))

.PHONY: test
test:
