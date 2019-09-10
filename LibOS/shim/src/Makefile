RUNTIME_DIR = $(CURDIR)/../../../Runtime

include ../../../Makefile.configs

OMIT_FRAME_POINTER = no

CFLAGS	+= -fPIC -Winline -Wwrite-strings \
	  -fmerge-all-constants -Wstrict-prototypes -Wtrampolines \
	  -Werror=implicit-function-declaration \
	  $(cc-option, -Wnull-dereference) \
	  -fno-stack-protector -fno-builtin -Wno-inline \
	  -I../include -I../../../Pal/lib -I../../../Pal/include/pal \
	  -I../../../Pal/include/elf

CFLAGS += -Wextra

ifeq ($(OMIT_FRAME_POINTER),yes)
CFLAGS += -DOMIT_FRAME_POINTER=1
else
CFLAGS += -fno-omit-frame-pointer -DOMIT_FRAME_POINTER=0
endif
ASFLAGS += -Wa,--noexecstack -x assembler-with-cpp -I../include

LDFLAGS += -shared -nostdlib -z combreloc -z relro -z now -z defs \
	  -dynamic-link=libpal.so \
	  -rpath-link=$(abspath $(RUNTIME_DIR))

files_to_build = libsysdb.a libsysdb.so libsysdb_debug.so
files_to_install = $(addprefix $(RUNTIME_DIR)/,$(files_to_build))

defs	= -DIN_SHIM
CFLAGS += $(defs)
ASFLAGS += $(defs)
fs	= chroot str pipe socket proc dev
ipcns	= pid sysv
objs	= $(addprefix bookkeep/shim_,handle vma thread signal) \
	  $(patsubst %.c,%,$(wildcard utils/*.c)) \
	  $(addprefix fs/shim_,dcache namei fs_hash fs) \
	  $(patsubst %.c,%,$(foreach f,$(fs),$(wildcard fs/$(f)/*.c))) \
	  $(addprefix ipc/shim_,ipc ipc_helper ipc_child) \
	  $(addprefix ipc/shim_ipc_,$(ipcns)) \
	  elf/shim_rtld \
	  $(addprefix shim_,init table syscalls checkpoint malloc \
	  async parser debug object) syscallas start \
	  $(patsubst %.c,%,$(wildcard sys/*.c)) \
	  vdso/vdso-data
all_objs = $(objs) vdso/vdso-note vdso/vdso

graphene_lib = .lib/graphene-lib.a
pal_lib = $(RUNTIME_DIR)/libpal-$(PAL_HOST).so

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
all: $(files_to_build) $(files_to_install)
else
all:
endif

$(files_to_install): $(RUNTIME_DIR)/%: %
	$(call cmd,ln_sf)

LDFLAGS-libsysdb.so += --version-script shim.map -T shim.lds
libsysdb.so: $(addsuffix .o,$(objs)) $(filter %.map %.lds,$(LDFLAGS-$@)) \
	     $(graphene_lib) $(pal_lib)
	$(call cmd,ld_so_o)

LDFLAGS-libsysdb_debug.so += --version-script shim-debug.map -T shim.lds
libsysdb_debug.so: $(addsuffix .o,$(filter-out syscallas,$(objs))) \
		   $(filter %.map %.lds,$(LDFLAGS-$@)) \
		   $(graphene_lib) $(pal_lib)
	$(call cmd,ld_so_o)

.PHONY: graphene_lib_recurse
graphene_lib_recurse:
	$(MAKE) -C ../../../Pal/lib target=$(abspath .lib)/

$(graphene_lib): graphene_lib_recurse
	@true

libsysdb.a: $(addsuffix .o,$(objs))
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

syscallas.S shim_checkpoint.c: asm-offsets.h

include ../../../Makefile.rules

LDFLAGS-vdso/vdso.so.dbg = -nostdlib -shared \
	--hash-style=both --build-id -Bsymbolic \
	-m elf_x86_64 --no-undefined \
	-z max-page-size=4096 -z common-page-size=4096 \
	-T vdso/vdso.lds -soname linux-vdso.so.1
vdso/vdso.so.dbg: LDFLAGS =
vdso/vdso.so.dbg: vdso/vdso.lds vdso/vdso.o vdso/vdso-note.o | vdso/.vdso-no-reloc-checked
	$(call cmd,ld)

# vdso.so is required to have no relocations. This rule checks it.
# Use default linker script to retain relocations if exist.
LDFLAGS-vdso/.vdso-linked-for-reloc-check.so = -nostdlib -shared -Bsymbolic
vdso/.vdso-linked-for-reloc-check.so: LDFLAGS =
vdso/.vdso-linked-for-reloc-check.so: vdso/vdso.o
	$(call cmd,ld)

vdso/.vdso-no-reloc-checked: vdso/.vdso-linked-for-reloc-check.so
	$(call cmd,check_no_reloc)
	$Q touch $@

OBJCOPYFLAGS-vdso/vdso.so = -S
vdso/vdso.so: vdso/vdso.so.dbg
	$(call cmd,objcopy)

vdso/vdso-data.o: vdso/vdso.so
CLEAN_FILES += vdso/vdso.so.dbg vdso/vdso.so vdso/.vdso-linked-for-reloc-check.so vdso/.vdso-no-reloc-checked

clean:
	rm -rf $(addsuffix .o,$(all_objs)) $(addsuffix .d,$(all_objs)) \
	       $(addsuffix .i.d,$(all_objs)) $(addsuffix .s.d,$(all_objs)) \
	       $(shim_target) $(files_to_build) .lib $(CLEAN_FILES)

-include $(addsuffix .d,$(all_objs)) $(addsuffix .i.d,$(all_objs)) $(addsuffix .s.d,$(all_objs))
