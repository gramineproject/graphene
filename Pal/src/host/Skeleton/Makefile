include ../../../../Makefile.configs
include Makefile.am

CFLAGS  += -I. -I../.. -I../../../include -I../../../lib
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Skeleton.a pal.map

defs	= -DIN_PAL
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc exception)

.PHONY: all
all: $(host_files)

libpal-Skeleton.a: $(addsuffix .o,$(objs))
	$(call cmd,ar_a_o)

%.o: %.c
	$(call cmd,cc_o_c)

%.o: %.S
	$(call cmd,as_o_S)

include ../../../../Makefile.rules

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(addsuffix .d,$(objs)) $(host_files) $(pal_lib)
