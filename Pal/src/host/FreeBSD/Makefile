include ../../../../Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../lib -I../../../ipc/linux \
	   -I../../../linux-kernel/graphene
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

host_target = libpal-FreeBSD.a pal-gdb

defs	= -DIN_PAL -DPAL_DIR="$(PAL_DIR)"
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc exception) rfork_thread
graphene_lib = .lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_target)

ifeq ($(DEBUG),1)
CC += -g -gdwarf-2 -gstrict-dwarf
CFLAGS += -DDEBUG
export DEBUG
endif

pal-gdb: pal-gdb.template
	sed -e 's:\$$(PAL_DIR):$(PWD):g' $< > $@
	chmod 755 $@

libpal-FreeBSD.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	$(call cmd,ar_a_o)

%.o: %.c $(headers)
	$(call cmd,cc_o_c)

%.i: %.c $(headers)
	$(call cmd,cpp_i_c)

%.s: %.c $(headers)
	$(call cmd,cc_s_c)

%.o: %.S $(headers)
	$(call cmd,as_o_S)

%.s: %.S $(headers)
	$(call cmd,cpp_s_S)


include ../../../../Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_target) $(CLEAN_FILES)
