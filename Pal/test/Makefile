include ../../Makefile.configs
include ../../Makefile.rules

CFLAGS += -fno-builtin -nostdlib -no-pie \
	  -I../include/pal -I../lib

executables = HelloWorld File Failure Thread Fork Event Process Exception \
	      Memory Pipe Tcp Udp Yield Broadcast Ipc Server Wait HandleSend \
	      Select Segment Sleep Cpuid Pie
manifests = manifest

target = $(executables) $(manifests)

include ../../Makefile.manifest

graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so

.PHONY: all
all:	pal_loader $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target))

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

pal_loader:
	ln -sf ../../Runtime/pal_loader

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
CFLAGS-Pie = -fPIC -pie
LDLIBS += $(graphene_lib) $(pal_lib) ../csu/user_start.o
$(executables): %: %.c $(LDLIBS)
	$(call cmd,csingle)

.lib/host_endian.h: ../src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../lib target=$(abspath .lib)/
else
.IGNORE: $(executables)
$(executables):
endif

ifeq ($(filter clean,$(MAKECMDGOALS)),)
-include $(addsuffix .d, $(executables)) $(addsuffix .i.d, $(executables)) $(addsuffix .s.d, $(executables))
endif

.PHONY: clean
clean:
	rm -rf pal_loader $(target) .lib *.cached *.sig *.token *.manifest.sgx \
	       $(addsuffix .d, $(executables)) $(addsuffix .i.d, $(executables)) \
	       $(addsuffix .s.d, $(executables)) \
	       $(addsuffix .manifest.sgx.d,$(executables)) \
		   .output.*
