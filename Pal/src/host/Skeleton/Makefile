include ../../../../Makefile.configs
include Makefile.am

CFLAGS  += -I. -I../.. -I../../../include -I../../../lib
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Skeleton.a pal.map

defs	= -DIN_PAL
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc exception)
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
export DEBUG
endif

../../host_endian.h: host_endian.h
	$(MAKE) -C ../../ $<

libpal-Skeleton.a: $(addsuffix .o,$(objs))
	@echo [ host/$(PAL_HOST)/$@ ]
	@$(AR) $(ARFLAGS) $@ $^

pal.map: pal.map.template ../../pal-symbols
	sed -e 's:\$$(PAL_SYMBOLS):$(shell sed -e 's:$$:;:g' ../../pal-symbols):g' $< > $@

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ host/$(PAL_HOST)/$@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.o: %.S $(headers)
	@echo [ host/$(PAL_HOST)/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files)
