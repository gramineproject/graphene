include ../../../../Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../lib -I../../../ipc/linux \
	   -I../../../linux-kernel/graphene
ASFLAGS += -I. -Iinclude -I../.. -I../../../include

host_files = libpal-FreeBSD.a pal.map ../../pal-gdb

defs	= -DIN_PAL -DPAL_DIR="$(PAL_DIR)"
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception2) rfork_thread
graphene_lib = .lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -g -gdwarf-2 -gstrict-dwarf
CFLAGS += -DDEBUG
export DEBUG
endif

pal-gdb: pal-gdb.template
	sed -e 's:\$$(PAL_DIR):$(PWD):g' $< > $@
	chmod 755 $@

libpal-FreeBSD.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ host/FreeBSD/$@ ]
	@$(AR) $(ARFLAGS) $@ $^

pal.map: pal.map.template ../../pal-symbols
	sed -e 's:\$$(PAL_SYMBOLS):$(shell sed -e 's:$$:;:g' ../../pal-symbols):g' $< > $@

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ host/FreeBSD/$@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.e %.i: %.c $(headers)
	@echo [ host/FreeBSD/$@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@

%.s: %.c $(headers)
	@echo [ host/FreeBSD/$@ ]
	@$(CC) $(CFLAGS) $(defs) -S $< -o $@

%.o: %.S $(headers)
	@echo [ host/FreeBSD/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

%.e %.s: %.S $(headers)
	@echo [ host/FreeBSD/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -E $< -o $@

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files) $(CLEAN_FILES)
