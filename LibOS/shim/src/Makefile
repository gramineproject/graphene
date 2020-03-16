RUNTIME_DIR = $(CURDIR)/../../../Runtime

include ../../../Scripts/Makefile.configs

CFLAGS += -fPIC -Winline -Wwrite-strings \
	  -fmerge-all-constants -Wstrict-prototypes -Wtrampolines \
	  -Werror=implicit-function-declaration \
	  $(cc-option, -Wnull-dereference) \
	  -fno-stack-protector -fno-builtin -Wno-inline \
	  -I../include -I../../../Pal/include/lib -I../../../Pal/include/pal \
	  -I../../../Pal/include/elf

CFLAGS += -Wextra

ASFLAGS += -Wa,--noexecstack -x assembler-with-cpp -I../include

LDFLAGS += -shared -nostdlib -z combreloc -z relro -z now -z defs \
	  -rpath-link=$(abspath $(RUNTIME_DIR))

files_to_build = libsysdb.a libsysdb.so libsysdb_debug.so
files_to_install = $(addprefix $(RUNTIME_DIR)/,$(files_to_build))

defs	= -DIN_SHIM
CFLAGS += $(defs)
ASFLAGS += $(defs)

objs = \
	shim_async.o \
	shim_checkpoint.o \
	shim_debug.o \
	shim_init.o \
	shim_malloc.o \
	shim_object.o \
	shim_parser.o \
	shim_syscalls.o \
	shim_table.o \
	start.o \
	syscallas.o \
	bookkeep/shim_handle.o \
	bookkeep/shim_signal.o \
	bookkeep/shim_thread.o \
	bookkeep/shim_vma.o \
	elf/shim_rtld.o \
	fs/shim_dcache.o \
	fs/shim_fs.o \
	fs/shim_fs_hash.o \
	fs/shim_namei.o \
	fs/chroot/fs.o \
	fs/dev/fs.o \
	fs/eventfd/fs.o \
	fs/pipe/fs.o \
	fs/proc/fs.o \
	fs/proc/info.o \
	fs/proc/ipc-thread.o \
	fs/proc/thread.o \
	fs/socket/fs.o \
	fs/str/fs.o \
	ipc/shim_ipc.o \
	ipc/shim_ipc_child.o \
	ipc/shim_ipc_helper.o \
	ipc/shim_ipc_pid.o \
	ipc/shim_ipc_sysv.o \
	sys/shim_access.o \
	sys/shim_alarm.o \
	sys/shim_benchmark.o \
	sys/shim_brk.o \
	sys/shim_clone.o \
	sys/shim_dup.o \
	sys/shim_epoll.o \
	sys/shim_eventfd.o \
	sys/shim_exec.o \
	sys/shim_exit.o \
	sys/shim_fcntl.o \
	sys/shim_fork.o \
	sys/shim_fs.o \
	sys/shim_futex.o \
	sys/shim_getcwd.o \
	sys/shim_getpid.o \
	sys/shim_getrlimit.o \
	sys/shim_ioctl.o \
	sys/shim_migrate.o \
	sys/shim_mmap.o \
	sys/shim_msgget.o \
	sys/shim_open.o \
	sys/shim_pipe.o \
	sys/shim_poll.o \
	sys/shim_sched.o \
	sys/shim_semget.o \
	sys/shim_sigaction.o \
	sys/shim_sleep.o \
	sys/shim_socket.o \
	sys/shim_stat.o \
	sys/shim_time.o \
	sys/shim_uname.o \
	sys/shim_vfork.o \
	sys/shim_wait.o \
	sys/shim_wrappers.o \
	utils/md5.o \
	utils/printf.o \
	utils/strobjs.o \
	vdso/vdso-data.o

all_objs = \
	$(objs) \
	vdso/vdso-note.o \
	vdso/vdso.o

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
libsysdb.so: $(objs) $(filter %.map %.lds,$(LDFLAGS-$@)) \
	     $(graphene_lib) $(pal_lib) shim.map shim.lds
	$(call cmd,ld_so_o)

LDFLAGS-libsysdb_debug.so += --version-script shim-debug.map -T shim.lds
libsysdb_debug.so: $(filter-out syscallas.o,$(objs)) \
		   $(filter %.map %.lds,$(LDFLAGS-$@)) \
		   $(graphene_lib) $(pal_lib) shim-debug.map shim.lds
	$(call cmd,ld_so_o)

.PHONY: graphene_lib_recurse
graphene_lib_recurse:
	$(MAKE) -C ../../../Pal/lib target=$(abspath .lib)/

$(graphene_lib): graphene_lib_recurse
	@true

libsysdb.a: $(objs)
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

include ../../../Scripts/Makefile.rules

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

.PHONY: clean
clean:
	$(RM) -r $(all_objs) $(patsubst %.o,%.d,$(all_objs)) \
	         $(patsubst %.o,%.i.d,$(all_objs)) $(patsubst %.o,%.s.d,$(all_objs)) \
	         $(shim_target) $(files_to_build) .lib $(CLEAN_FILES)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
-include $(patsubst %.o,%.d,$(all_objs)) $(patsubst %.o,%.i.d,$(all_objs)) $(patsubst %.o,%.s.d,$(all_objs))
endif

.PHONY: distclean
distclean: clean
