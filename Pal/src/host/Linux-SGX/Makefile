include ../../../../Scripts/Makefile.configs
include Makefile.am

CFLAGS += -I. -Iinclude -I../.. -I../../../include -I../../../include/pal \
          -I../../../lib/crypto/mbedtls/include -I../../../lib/crypto/mbedtls/crypto/include \
          -I../../../include/host/Linux-SGX \
          -I../../../include/host/Linux-common \
          -I../../../include/lib -Isgx-driver
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Linux-SGX.a pal-sgx debugger/sgx_gdb.so pal.map generated_offsets.py

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
CFLAGS += $(defs)
ASFLAGS += $(defs)

commons_objs = bogomips.o

enclave-objs = \
	db_devices.o \
	db_eventfd.o \
	db_events.o \
	db_exception.o \
	db_files.o \
	db_main.o \
	db_memory.o \
	db_misc.o \
	db_mutex.o \
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
	enclave_platform.o \
	enclave_untrusted.o \
	enclave_xstate.o \
	$(commons_objs)

enclave-asm-objs = enclave_entry.o

urts-objs = \
	clone-x86_64.o \
	sgx_enclave.o \
	sgx_exception.o \
	sgx_framework.o \
	sgx_graphene.o \
	sgx_main.o \
	sgx_platform.o \
	sgx_process.o \
	sgx_rtld.o \
	sgx_thread.o \
	quote/aesm.pb-c.o

urts-asm-objs = sgx_entry.o

graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: sgx-driver/sgx.h $(host_files)

libpal-Linux-SGX.a: $(enclave-objs) $(enclave-asm-objs)
	$(call cmd,ar_a_o)

$(enclave-objs): CFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.i,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.s,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(enclave-asm-objs): ASFLAGS += -DIN_ENCLAVE
$(patsubst %.o,%.s,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE

$(urts-objs): quote/aesm.pb-c.h

$(commons_objs): %.o: ../Linux-common/%.c
	$(call cmd,cc_o_c)

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

debugger/sgx_gdb.so: CFLAGS =
CFLAGS-debugger/sgx_gdb.so = -shared -Wall -fPIC -O2 -std=c11
debugger/sgx_gdb.so: debugger/sgx_gdb.c
	$(call cmd,csingle)

enclave_entry.o sgx_entry.o: asm-offsets.h

sgx-driver/sgx.h:
	$(MAKE) -C sgx-driver $(notdir $@)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d) $(wildcard debugger/*.d)
endif

include ../../../../Scripts/Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_loader))
CLEAN_FILES += debugger/sgx_gdb.so
CLEAN_FILES += quote/aesm.pb-c.c quote/aesm.pb-c.h quote/aesm.pb-c.d quote/aesm.pb-c.o

.PHONY: clean_
clean_:
	$(RM) -r *.o *.e *.i *.s $(host_files) $(CLEAN_FILES) *.d debugger/*.d signer/*.pyc __pycache__ \
	         signer/__pycache__

.PHONY: clean
clean: clean_
	$(MAKE) -C sgx-driver $@

.PHONY: distclean
distclean: clean_
	$(MAKE) -C sgx-driver $@

.PHONY: test
test:
