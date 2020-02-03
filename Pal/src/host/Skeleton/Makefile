include ../../../../Scripts/Makefile.configs
include Makefile.am

CFLAGS  += -I. -I../.. -I../../../include  -I../../../include/pal \
	-I../../../include/host/Skeleton -I../../../include/lib
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Skeleton.a pal.map

defs	= -DIN_PAL
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes eventfd sockets streams memory threading \
	    mutex events process object main rtld misc exception)

.PHONY: all
all: $(host_files)

libpal-Skeleton.a: $(addsuffix .o,$(objs))
	$(call cmd,ar_a_o)

%.o: %.c
	$(call cmd,cc_o_c)

%.o: %.S
	$(call cmd,as_o_S)

include ../../../../Scripts/Makefile.rules

.PHONY: clean
clean:
	$(RM) $(addsuffix .o,$(objs)) $(addsuffix .d,$(objs)) $(host_files) $(pal_lib)

.PHONY: distclean
distclean: clean
