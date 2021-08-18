include ../../../../Scripts/Makefile.configs
include Makefile.am

CFLAGS += \
	-I. \
	-I../.. \
	-I../../../../common/include \
	-I../../../../common/include/arch/$(ARCH) \
	-I../../../../common/src/crypto/mbedtls/include \
	-I../../../include \
	-I../../../include/pal \
	-I../../../include/arch/$(ARCH) \
	-I../../../include/arch/$(ARCH)/Linux \
	-I../../../include/host/Linux-SGX \
	-I../../../include/host/Linux-common \
	-Iprotected-files

# Some of the code uses alignof on expressions, which is a GNU extension.
# Silence Clang - it complains but does support it.
CFLAGS += $(call cc-option,-Wno-gnu-alignof-expression)

CFLAGS += $(CFLAGS_SANITIZERS)

ASFLAGS += \
	-I. \
	-I../.. \
	-I../../../include \
	-I../../../include/arch/$(ARCH)/Linux

host_files = libpal-Linux-SGX.a pal-sgx gdb_integration/sgx_gdb.so pal.map generated_offsets.py

defs	= -DIN_PAL
CFLAGS += $(defs)
ASFLAGS += $(defs)

commons_objs_encl = bogomips.o graphene_unix_socket_addr.o
commons_objs_urts = debug_map.o file_utils.o main_exec_path.o timespec_utils.o topo_info.o

enclave-objs = \
	db_devices.o \
	db_eventfd.o \
	db_events.o \
	db_exception.o \
	db_files.o \
	db_main.o \
	db_memory.o \
	db_misc.o \
	db_object.o \
	db_pipes.o \
	db_process.o \
	db_rtld.o \
	db_sockets.o \
	db_streams.o \
	db_threading.o \
	enclave_ecalls.o \
	enclave_framework.o \
	enclave_ocalls.o \
	enclave_pages.o \
	enclave_pf.o \
	enclave_platform.o \
	enclave_untrusted.o \
	enclave_xstate.o \
	protected-files/lru_cache.o \
	protected-files/protected_files.o \
	$(commons_objs_encl)

enclave-asm-objs = enclave_entry.o

urts-objs = \
	sgx_enclave.o \
	sgx_exception.o \
	sgx_framework.o \
	sgx_gdb_info.o \
	sgx_log.o \
	sgx_main.o \
	sgx_perf_data.o \
	sgx_platform.o \
	sgx_process.o \
	sgx_profile.o \
	sgx_profile_glibc.o \
	sgx_syscall.o \
	sgx_thread.o \
	quote/aesm.pb-c.o \
	common_syscall.o \
	$(commons_objs_urts)

urts-asm-objs = sgx_entry.o

graphene_lib = .lib/graphene-lib.a

# use TLS-based stack protector of GCC (trusted PAL must have a canary in its PAL_TCB at offset
# 0x8, untrusted PAL uses the default GCC scheme)
# not all compilers support mstack-protector-guard, so use stack protector only if supported
CFLAGS += -fno-stack-protector
ifeq ($(ARCH),x86_64)
$(enclave-objs): CFLAGS += $(call cc-option, -fstack-protector-strong -mstack-protector-guard=tls \
                             -mstack-protector-guard-reg=%gs -mstack-protector-guard-offset=8)
$(urts-objs): CFLAGS += $(call cc-option, -fstack-protector-strong)
endif

.PHONY: all
all: gsgx.h $(host_files) tools

libpal-Linux-SGX.a: $(enclave-objs) $(enclave-asm-objs)
	$(call cmd,ar_a_o)

$(enclave-objs): CFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.i,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.s,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(enclave-asm-objs): ASFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.s,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE

$(urts-objs): quote/aesm.pb-c.h

$(commons_objs_encl) $(commons_objs_urts): %.o: ../Linux-common/%.c
	$(call cmd,cc_o_c)

common_syscall.o: ../Linux-common/arch/$(ARCH)/syscall.S
	$(call cmd,as_o_S)

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

CFLAGS-pal-sgx = -Wl,-z,relro,-z,now -pie
LDLIBS-pal-sgx += -lprotobuf-c
pal-sgx: $(urts-objs) $(urts-asm-objs) $(graphene_lib)
	$(call cmd,cmulti)

quote/aesm.pb-c.o: quote/aesm.pb-c.c quote/aesm.pb-c.h
quote/aesm.pb-c.c quote/aesm.pb-c.h: quote/aesm.proto
	@echo [ host/Linux-SGX/quote/aesm.pb-c.c ]
	@echo [ host/Linux-SGX/quote/aesm.pb-c.h ]
	@protoc-c --c_out=. $<

gdb_integration/sgx_gdb.so: CFLAGS =
CFLAGS-gdb_integration/sgx_gdb.so = -shared -Wall -fPIC -O2 -std=c11
gdb_integration/sgx_gdb.so: gdb_integration/sgx_gdb.c
	$(call cmd,csingle)

enclave_entry.o sgx_entry.o: asm-offsets.h

gsgx.h: gsgx.h.in
	./link-intel-driver.py --input $< --output $@

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d) $(wildcard gdb_integration/*.d)
endif

include ../../../../Scripts/Makefile.rules

.PHONY: tools
tools:
	$(MAKE) -C tools

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_loader))
CLEAN_FILES += gdb_integration/sgx_gdb.so
CLEAN_FILES += quote/aesm.pb-c.c quote/aesm.pb-c.h quote/aesm.pb-c.d quote/aesm.pb-c.o
CLEAN_FILES += gsgx.h

.PHONY: clean_
clean_:
	$(RM) -r *.o *.e *.i *.s $(host_files) $(CLEAN_FILES) *.d gdb_integration/*.d signer/*.pyc \
	         __pycache__ signer/__pycache__
	$(RM) -r protected-files/*.o protected-files/*.d

.PHONY: clean
clean: clean_
	$(MAKE) -C tools $@

.PHONY: distclean
distclean: clean_
	$(MAKE) -C tools $@

.PHONY: test
test:
