include ../../../../Makefile.configs
include Makefile.am

CFLAGS	+= -I. -Iinclude -I../.. -I../../../include -I../../../lib -Isgx-driver
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Linux-SGX.a pal-sgx debugger/sgx_gdb.so generated_offsets.py

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
CFLAGS += $(defs)
ASFLAGS += $(defs)
enclave-objs = $(addprefix db_,files devices pipes sockets streams memory \
		 threading mutex events process object main rtld \
		 exception misc ipc spinlock) \
	       $(addprefix enclave_,ocalls ecalls framework pages untrusted)
enclave-asm-objs = enclave_entry
urts-objs = $(addprefix sgx_,enclave framework main rtld thread process exception graphene)
urts-asm-objs = sgx_entry
graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
ASFLAGS += -DDEBUG
export DEBUG
endif

../../host_endian.h: host_endian.h
	$(MAKE) -C ../../ $<

libpal-Linux-SGX.a: $(addsuffix .o,$(enclave-objs) $(enclave-asm-objs))
	$(call cmd,ar_a_o)

$(addsuffix .o,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .i,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .s,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .o,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE
$(addsuffix .s,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE

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

pal-sgx: $(addsuffix .o,$(urts-objs) $(urts-asm-objs)) $(graphene_lib)
	@echo [ host/Linux-SGX/$@ ]
	@$(CC) $(CFLAGS) -Wl,-z,relro,-z,now -pie $^ -lc -pthread -o $@

debugger/sgx_gdb.so: debugger/sgx_gdb.c debugger/sgx_gdb.h sgx_arch.h
	@echo [ host/Linux-SGX/$@ ]
	$(CC) -MD -MP -Wall -fPIC -O2 -std=c11 -c debugger/sgx_gdb.c -o debugger/sgx_gdb.o
	$(LD) -shared debugger/sgx_gdb.o -o debugger/sgx_gdb.so -lc

enclave_entry.o sgx_entry.o: asm-offsets.h

sgx-driver/isgx_version.h:
	$(MAKE) -C sgx-driver $(notdir $<)

include $(wildcard *.d) $(wildcard debugger/*.d)

include ../../../../Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_loader))
CLEAN_FILES += debugger/sgx_gdb.o

.PHONY: clean
clean:
	rm -f *.o *.e *.i *.s $(host_files) $(CLEAN_FILES) *.d debugger/*.d

.PHONY: test
test:
