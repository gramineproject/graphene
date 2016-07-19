CC	= gcc
AS	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE \
	  -fno-omit-frame-pointer \
	  -fno-stack-protector -fno-builtin \
	  -I. -Iinclude -I../.. -I../../../include -I../../../lib -I../../../ipc/linux \
	  -I../../../linux-kernel/graphene
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp \
	  -I. -Iinclude -I../.. -I../../../include
ARFLAGS	=

ifeq ($(PROFILING),1)
CFLAGS	+= -DPROFILING=1
endif

host_target = libpal-Linux.a

defs	= -DIN_PAL -DPAL_DIR="$(PAL_DIR)"
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    semaphore mutex events process object main rtld misc ipc \
	    exception) manifest clone-x86_64 gettimeofday-x86_64
graphene_lib = ../../.lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

all: $(host_target)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
export DEBUG
endif

../../host_endian.h: host_endian.h
	$(MAKE) -C ../.. $<

libpal-Linux.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ host/Linux/$@ ]
	@$(AR) $(ARFLAGS) $@ $^

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ host/Linux/$@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.e: %.c $(headers)
	@echo [ host/Linux/$@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@

%.o: %.S $(headers)
	@echo [ host/Linux/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

%.e: %.S $(headers)
	@echo [ host/Linux/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -E $< -o $@

clean:
	rm -f $(addsuffix .o,$(objs)) $(host_target)
