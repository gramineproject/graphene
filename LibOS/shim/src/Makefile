RUNTIME_DIR = $(CURDIR)/../../../Runtime

include ../../../Pal/src/Makefile.Host

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

EXTRAFLAGS = -Wextra -Wno-unused-parameter -Wno-sign-compare

CFLAGS += $(EXTRAFLAGS)

ifeq ($(OMIT_FRAME_POINTER),yes)
CFLAGS += -DOMIT_FRAME_POINTER=1
else
CFLAGS += -fno-omit-frame-pointer -DOMIT_FRAME_POINTER=0
endif
ASFLAGS	= -Wa,--noexecstack -x assembler-with-cpp -I../include

LDFLAGS	= -shared -nostdlib --version-script shim.map -T shim.lds \
	  -z combreloc -z relro -z defs \
	  -dynamic-link=libpal.so \
	  -rpath-link=$(abspath $(RUNTIME_DIR))
LDFLAGS-debug = $(patsubst shim.map,shim-debug.map,$(LDFLAGS))
ARFLAGS	=

files_to_build = libsysdb.a libsysdb.so libsysdb_debug.so
files_to_install = $(addprefix $(RUNTIME_DIR)/,$(files_to_build))

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
pal_lib = $(RUNTIME_DIR)/libpal-$(PAL_HOST).so
headers = ../include/*.h ../../../Pal/lib/*.h ../../../Pal/include/pal/*.h

all: $(files_to_build) $(files_to_install)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
ASFLAGS += -DDEBUG
endif
export DEBUG

ifeq ($(PROFILING), 1)
CFLAGS += -DPROFILE
endif

$(files_to_install): $(RUNTIME_DIR)/%: %
	cp -f $< $@

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
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

.lib/host_endian.h: ../../../Pal/src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

.PHONY: $(graphene_lib)
$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../../../Pal/lib target=$(abspath .lib)/

libsysdb.a: $(addsuffix .o,$(objs))
	@echo [ $@ ]
	$(AR) $(ARFLAGS) $@ $^
else
.IGNORE: $(shim_target)
$(shim_target):
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
