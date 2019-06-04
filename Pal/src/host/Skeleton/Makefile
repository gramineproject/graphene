include ../../../../Makefile.configs
include Makefile.am

CFLAGS  += -I. -I../.. -I../../../include -I../../../lib
ASFLAGS += -I. -I../.. -I../../../include

host_target = libpal-Skeleton.a

defs	= -DIN_PAL
CFLAGS += $(defs)
ASFLAGS += $(defs)
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    semaphore events process object main rtld misc ipc exception)
graphene_lib = ../../../lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_target)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
export DEBUG
endif

../../host_endian.h: host_endian.h
	$(MAKE) -C ../../ $<

libpal-Skeleton.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	$(call cmd,ar_a_o)

%.o: %.c $(headers)
	$(call cmd,cc_o_c)

%.o: %.S $(headers)
	$(call cmd,as_o_S)

include ../../../../Makefile.rules

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_target)
