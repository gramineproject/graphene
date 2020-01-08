include ../../../../Scripts/Makefile.configs
include Makefile.am

ias_cert_url ?= https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem
ias_cert_sha256 ?= e7b9113b647bc6bd421d4f140076a3acc31e410e01bf12883841e824cdaf1564
ias_cert_file = quote/$(notdir $(ias_cert_url))

CFLAGS += -I. -Iinclude -I../.. -I../../../include -I../../../include/pal \
	-I../../../lib/crypto/mbedtls/include -I../../../include/host/Linux-SGX \
	-I../../../include/lib -Isgx-driver
ASFLAGS += -I. -I../.. -I../../../include

host_files = libpal-Linux-SGX.a pal-sgx debugger/sgx_gdb.so pal.map generated_offsets.py

defs	= -DIN_PAL -DPAL_DIR=$(PAL_DIR) -DRUNTIME_DIR=$(RUNTIME_DIR)
CFLAGS += $(defs)
ASFLAGS += $(defs)
enclave-objs = $(addprefix db_,files devices pipes eventfd sockets streams memory \
		threading mutex events process object main rtld \
		exception misc) \
		$(addprefix enclave_,ocalls ecalls framework pf platform pages untrusted xstate) \
		lru_cache protected_files
enclave-asm-objs = enclave_entry
urts-objs = $(addprefix sgx_,enclave framework platform main rtld thread process exception graphene) \
	    quote/aesm.pb-c clone-x86_64
urts-asm-objs = sgx_entry
graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: sgx-driver/isgx_version.h $(host_files) tools

libpal-Linux-SGX.a: $(addsuffix .o,$(enclave-objs) $(enclave-asm-objs))
	$(call cmd,ar_a_o)

$(addsuffix .o,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .i,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .s,$(enclave-objs)): CFLAGS += -DIN_ENCLAVE
$(addsuffix .o,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE
$(addsuffix .s,$(enclave-asm-objs)): ASFLAGS += -DIN_ENCLAVE

$(addsuffix .o,$(urts-objs)): quote/aesm.pb-c.h
$(addsuffix .o,$(enclave-objs)): quote/generated-cacert.h

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
pal-sgx: $(addsuffix .o,$(urts-objs) $(urts-asm-objs)) $(graphene_lib)
	$(call cmd,cmulti)

quote/aesm.pb-c.o: quote/aesm.pb-c.c quote/aesm.pb-c.h
quote/aesm.pb-c.c quote/aesm.pb-c.h: quote/aesm.proto
	@echo [ host/Linux-SGX/quote/aesm.pb-c.c ]
	@echo [ host/Linux-SGX/quote/aesm.pb-c.h ]
	@protoc-c --c_out=. $<

quote/generated-cacert.h: $(ias_cert_file)
	@echo "#define IAS_CA_CERT \"$(shell cat $< | tr -d '[\r\n]')\"" > $@

$(ias_cert_file):
	@../../../../Scripts/download --output $@ --url $(ias_cert_url) --sha256 $(ias_cert_sha256)

debugger/sgx_gdb.so: CFLAGS =
CFLAGS-debugger/sgx_gdb.so = -shared -Wall -fPIC -O2 -std=c11
debugger/sgx_gdb.so: debugger/sgx_gdb.c
	$(call cmd,csingle)

enclave_entry.o sgx_entry.o: asm-offsets.h

sgx-driver/isgx_version.h:
	$(MAKE) -C sgx-driver $(notdir $@)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d) $(wildcard debugger/*.d)
endif

.PHONY: tools
tools:
	@$(MAKE) -C tools

include ../../../../Scripts/Makefile.rules

CLEAN_FILES += $(notdir $(pal_static) $(pal_lib) $(pal_loader))
CLEAN_FILES += debugger/sgx_gdb.so
CLEAN_FILES += quote/aesm.pb-c.c quote/aesm.pb-c.h quote/aesm.pb-c.d quote/aesm.pb-c.o
CLEAN_FILES += quote/generated-cacert.h

.PHONY: clean_
clean_:
	$(RM) -r *.o *.e *.i *.s $(host_files) $(CLEAN_FILES) *.d debugger/*.d signer/*.pyc __pycache__ \
	         signer/__pycache__

.PHONY: clean
clean: clean_
	$(MAKE) -C sgx-driver $@

.PHONY: distclean
distclean: clean_
	$(RM) $(ias_cert_file)
	$(MAKE) -C sgx-driver $@
	$(MAKE) -C tools clean

.PHONY: test
test:
