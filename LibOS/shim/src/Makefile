SYS ?= $(shell gcc -dumpmachine)
export SYS

CC	= gcc
AS	= gcc
AR	= ar rcs
LD	= ld

OMIT_FRAME_POINTER = no

CFLAGS	= -Wall -fPIC -std=gnu99 -fgnu89-inline -Winline -Wwrite-strings \
	  -fmerge-all-constants -Wstrict-prototypes \
	  -Werror=implicit-function-declaration \
	  -fno-stack-protector -fno-builtin -Wno-inline \
	  -I../include -I../../../Pal/lib -I../../../Pal/include/pal
ifeq ($(OMIT_FRAME_POINTER),yes)
CFLAGS += -DOMIT_FRAME_POINTER=1
else
CFLAGS += -fno-omit-frame-pointer -DOMIT_FRAME_POINTER=0
endif
ASFLAGS	= -Wa,--noexecstack -x assembler-with-cpp -I../include

LDFLAGS	= -shared -nostdlib --version-script shim.map -T shim.lds \
	  -z combreloc -z relro -z defs \
	  -dynamic-link=libpal.so \
	  -rpath-link=$(abspath ../../../Pal/src)
LDFLAGS-debug = $(patsubst shim.map,shim-debug.map,$(LDFLAGS))
ARFLAGS	=

shim_target = libsysdb.a libsysdb.so libsysdb_debug.so

defs	= -DIN_SHIM
fs	= chroot str pipe socket proc dev
ipcns	= pid sysv
objs	= $(addprefix bookkeep/shim_,handle vma thread signal) \
	  $(patsubst %.c,%,$(wildcard utils/*.c)) \
	  $(addprefix fs/shim_,dcache namei fs_hash fs) \
	  $(patsubst %.c,%,$(foreach f,$(fs),$(wildcard fs/$(f)/*.c))) \
	  $(addprefix ipc/shim_,ipc ipc_helper ipc_child) \
	  $(addprefix ipc/shim_ipc_,$(ipcns)) \
	  elf/shim_rtld \
	  $(addprefix shim_,init table syscalls checkpoint random malloc \
	  async parser debug) syscallas start \
	  $(patsubst %.c,%,$(wildcard sys/*.c))
graphene_lib = .lib/graphene-lib.a
pal_lib = $(abspath ../../../Pal/src/libpal.so)
headers = ../include/*.h ../../../Pal/lib/*.h ../../../Pal/include/pal/*.h

all: $(shim_target)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
ASFLAGS += -DDEBUG
endif
export DEBUG

ifeq ($(PROFILING), 1)
CFLAGS += -DPROFILE
endif

ifeq ($(SYS),x86_64-linux-gnu)
libsysdb.so: $(addsuffix .o,$(objs)) $(filter %.map %.lds,$(LDFLAGS)) \
	     $(graphene_lib) $(pal_lib)
	@echo [ $@ ]
	$(LD) $(LDFLAGS) -o $@ $(filter-out %.map %.lds,$^) -soname $@ \
		-e shim_start

libsysdb_debug.so: $(addsuffix .o,$(filter-out syscallas,$(objs))) \
		   $(filter %.map %.lds,$($LDFLAGS-debug)) \
		   $(graphene_lib) $(pal_lib)
	@echo [ $@ ]
	$(LD) $(LDFLAGS-debug) -o $@ $(filter-out %.map %.lds,$^) -soname $@ \
		-e shim_start

.PHONY: $(graphene_lib)
$(graphene_lib):
	$(MAKE) -C ../../../Pal/lib $(debug) target=$(shell pwd)/.lib/

libsysdb.a: $(addsuffix .o,$(objs))
	@echo [ $@ ]
	$(AR) $(ARFLAGS) $@ $^

.PHONY: pack
pack: $(shim_target) $(addsuffix .o,$(objs))
	@../../../Scripts/pack_binaries.sh shim $^
else
$(shim_target): .packed/shim.tar.gz
	tar -xmozf $< $@
endif

%.asm: %.c $(headers)
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(defs) -c $< -o $<.o
	@objdump -S $<.o > $@
	@rm $<.o

$(addsuffix .o,$(addprefix ipc/shim_ipc_,$(ipcns))): $(wildcard ipc/*.h)
elf/shim_rtld.o: $(wildcard elf/*.h)


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
	rm -rf $(addsuffix .o,$(objs)) $(shim_target) .lib
