MAKEFLAGS += --check-symlink-times

root	= ../../../
include ../../../Makefile.in

OMIT_FRAME_POINTER = no

CC	= gcc
AS	= gcc
AR	= ar rcs

CFLAGS	= -Wall -fPIC -O2 -std=gnu99 -fgnu89-inline -Wall -U_FORTIFY_SOURCE \
	  -fno-stack-protector -fno-builtin \
	  -I. -I../.. -I../../../include -I$(lib_dir) -I$(ipc_dir) -I$(kernel_dir)
ifeq ($(OMIT_FRAME_POINTER),yes)
	cflags += -DOMIT_FRAME_POINTER=1
else
	cflags += -DOMIT_FRAME_POINTER=0 -fno-omit-frame-pointer
endif
ASFLAGS = -DPIC -DSHARED -fPIC -DASSEMBLER -Wa,--noexecstack \
	  -x assembler-with-cpp \
	  -I. -I../.. -I../../../include
ARFLAGS	=

host_target = libpal-Skeleton.a

defs	= -DIN_PAL -DSRCDIR="$(PWD)/"
objs	= $(addprefix db_,files devices pipes sockets streams memory threading \
	    semaphore mutex events process object main rtld misc ipc \
	    exception) clone-x86_64 gettimeofday-x86_64
graphene_lib = $(lib_dir)/graphene-lib.a
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard $(lib_dir)/*.h)

all: $(host_target)

debug: debug = debug
debug: CC = gcc -g
debug: CFLAGS += -DDEBUG
debug: $(host_target)

$(graphene_lib):
	make -C $(lib_dir) $(debug)

libpal-Skeleton.a: $(addsuffix .o,$(objs)) $(graphene_lib)
	@echo [ $@ ]
	@[ ! -f $@ ] || mv -f $@ $@.backup
	@$(AR) $(ARFLAGS) $@ $^

%.asm: %.c $(headers)
	$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

%.o: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $@

%.e: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -E $< -o $@

%.o: %.S $(headers)
	@echo [ $@ ]
	@$(AS) $(ASFLAGS) $(defs) -c $< -o $@

%.e: %.S $(headers)
	@echo [ $@ ]
	@$(AS) $(ASFLAGS) $(defs) -E $< -o $@

clean:
	rm -rf $(addsuffix .o,$(objs))
	for f in $(host_target); \
	do \
		[ ! -f $$f ] || mv -f $$f $$f.backup || true; \
	done
