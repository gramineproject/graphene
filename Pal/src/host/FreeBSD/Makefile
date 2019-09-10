include ../../../../Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../lib -I../../../ipc/linux \
	   -I../../../linux-kernel/graphene
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

host_files = libpal-FreeBSD.a pal.map ../../pal-gdb

defs	= -DIN_PAL -DPAL_DIR="$(PAL_DIR)"
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception2) rfork_thread
graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CFLAGS += -gstrict-dwarf
endif

pal-gdb: pal-gdb.template
	sed -e 's:\$$(PAL_DIR):$(PWD):g' $< > $@
	chmod 755 $@

libpal-FreeBSD.a: $(addsuffix .o,$(objs)) $(graphene_lib)
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

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files) $(CLEAN_FILES)
