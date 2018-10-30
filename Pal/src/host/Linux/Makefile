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
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    mutex events process object main rtld misc ipc \
	    exception) manifest clone-x86_64 gettimeofday-x86_64
graphene_lib = .lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
export DEBUG
endif

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

.PHONY: clean
clean:
	rm -f $(addsuffix .o,$(objs)) $(host_files)
