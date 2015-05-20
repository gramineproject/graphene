CC	= gcc
AS	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE \
	  -fno-builtin -I. -I../.. -I../../../include -I../../../lib
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp \
	  -I. -I../.. -I../../../include
ARFLAGS	=

host_target = libpal-Skeleton.a

defs	= -DIN_PAL -DSRCDIR="$(PWD)/"
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    semaphore events process object main rtld misc ipc exception)
graphene_lib = ../../../lib/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h)

all: $(host_target)

debug: debug = debug
debug: CC = gcc -g
debug: CFLAGS += -DDEBUG
debug: $(host_target)

$(graphene_lib): ../../host_endian.h
	make -C ../../../lib $(debug)

../../host_endian.h: host_endian.h
	make -C ../../ $<

libpal-Skeleton.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ host/$(OS)/$@ ]
	@$(AR) $(ARFLAGS) $@ $^

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ host/$(OS)/$@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.o: %.S $(headers)
	@echo [ host/$(OS)/$@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

clean:
	rm -f $(addsuffix .o,$(objs)) $(host_target)
