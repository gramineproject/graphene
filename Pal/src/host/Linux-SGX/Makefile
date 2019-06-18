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
headers	= $(wildcard *.h) $(wildcard ../../*.h) $(wildcard ../../../lib/*.h) \
	  $(addprefix sgx-driver/,graphene-sgx.h isgx_version.h)

.PHONY: all
all: $(host_files)

ifeq ($(DEBUG),1)
CC += -gdwarf-2 -g3
CFLAGS += -DDEBUG
ASFLAGS += -DDEBUG
export DEBUG
endif

.Makefile.stack-protector: asm-offsets.h
       $(call cmd,makefile_stack_protector)

CFLAGS_ENCLAVE += -DIN_ENCLAVE
ASFLAGS_ENCLAVE += -DIN_ENCLAVE

ifeq ($(CONFIG_PAL_STACK_PROTECTOR),y)
include .Makefile.stack-protector
$(addsuffix .o,$(objs)): .Makefile.stack-protector
ASFLAGS += -DENABLE_STACK_PROTECTOR=1
CFLAGS += -DENABLE_STACK_PROTECTOR=1
ifneq ($(CONFIG_STACK_PROTECTOR_GUARD_OFFSET),)
CFLAGS_ENCLAVE += -mstack-protector-guard-offset=$(CONFIG_STACK_PROTECTOR_GUARD_OFFSET)
endif
CFLAGS_ENCLAVE += -mstack-protector-guard-reg=%gs
CFLAGS_URTS += -fstack-protector
else
CFLAGS += -fno-stack-protector
endif

../../host_endian.h: host_endian.h
	$(MAKE) -C ../../ $<

libpal-Linux-SGX.a: $(addsuffix .o,$(enclave-objs) $(enclave-asm-objs))
	$(call cmd,ar_a_o)

$(addsuffix .o,$(enclave-objs)): CFLAGS += $(CFLAGS_ENCLAVE)
$(addsuffix .o,$(enclave-objs)): %.o: %.c $(headers)
	$(call cmd,cc_o_c)

$(addsuffix .i,$(enclave-objs)): CFLAGS += $(CFLAGS_ENCLAVE)
$(addsuffix .i,$(enclave-objs)): %.i: %.c $(headers)
	$(call cmd,cpp_i_c)

$(addsuffix .s,$(enclave-objs)): CFLAGS += $(CFLAGS_ENCLAVE)
$(addsuffix .s,$(enclave-objs)): %.s: %.c $(headers)
	$(call cmd,cc_s_c)

$(addsuffix .o,$(enclave-asm-objs)): ASFLAGS += $(ASFLAGS_ENCLAVE)
$(addsuffix .o,$(enclave-asm-objs)): %.o: %.S $(headers)
	$(call cmd,as_o_S)

$(addsuffix .s,$(enclave-asm-objs)): ASFLAGS += $(ASFLAGS_ENCLAVE)
$(addsuffix .s,$(enclave-asm-objs)): %.s: %.S $(headers)
	$(call cmd,cpp_s_S)

$(addsuffix .o,$(urts-objs)): CFLAGS += $(CFLAGS_URTS)
$(addsuffix .o,$(urts-objs)): %.o: %.c $(headers)
	$(call cmd,cc_o_c)

$(addsuffix .i,$(urts-objs)): CFLAGS += $(CFLAGS_URTS)
$(addsuffix .i,$(urts-objs)): %.i: %.c $(headers)
	$(call cmd,cpp_i_c)

$(addsuffix .s,$(urts-objs)): CFLAGS += $(CFLAGS_URTS)
$(addsuffix .s,$(urts-objs)): %.s: %.c $(headers)
	$(call cmd,cc_s_c)

$(addsuffix .s,$(urts-asm-objs)): %.s: %.S $(headers)
	$(call cmd,cpp_s_S)

$(addsuffix .o,$(urts-asm-objs)): %.o: %.S $(headers)
	$(call cmd,as_o_S)

pal-sgx: $(addsuffix .o,$(urts-objs) $(urts-asm-objs)) $(graphene_lib)
	@echo [ host/Linux-SGX/$@ ]
	@$(CC) $(CFLAGS) -pie $^ -lc -pthread -o $@

debugger/sgx_gdb.so: debugger/sgx_gdb.c debugger/sgx_gdb.h sgx_arch.h
	@echo [ host/Linux-SGX/$@ ]
	$(CC) -Wall -fPIC -O2 -std=c11 -c debugger/sgx_gdb.c -o debugger/sgx_gdb.o
	$(LD) -shared debugger/sgx_gdb.o -o debugger/sgx_gdb.so -lc

enclave_entry.o sgx_entry.o: asm-offsets.h

sgx-driver/isgx_version.h:
	$(MAKE) -C sgx-driver $(notdir $<)

include ../../../../Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_sec) $(pal_loader))
CLEAN_FILES += debugger/sgx_gdb.o

.PHONY: clean
clean:
	rm -f *.o *.e *.i *.s $(host_files) $(CLEAN_FILES)
