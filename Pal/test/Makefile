include ../src/Makefile.Host

CC	= gcc
CFLAGS	= -Wall -O2 -std=c11 -fno-builtin -nostdlib -no-pie \
	  -I../include/pal -I../lib

.PHONY: default
default: all
include ../../Makefile.configs
include ../../Makefile.rules
include ../src/Makefile.Test

executables = HelloWorld File Failure Thread Fork Event Process Exception \
	      Memory Pipe Tcp Udp Yield Broadcast Ipc Server Wait HandleSend \
	      Select Segment Sleep Cpuid Pie
manifests = manifest

target = $(executables) $(manifests)

graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so

.PHONY: all
all:	pal_loader $(call expand_target,$(target))

ifeq ($(DEBUG),1)
CC += -g
endif
export DEBUG

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

pal_loader:
	ln -sf ../../Runtime/pal_loader

manifest: manifest.template
	cp -f $< $@

%.manifest: %.manifest.template
	cp -f $< $@

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
CFLAGS-Pie = -fPIC -pie
LDLIBS = $(graphene_lib) $(pal_lib) ../src/user_start.o
$(executables): %: %.c $(LDLIBS)
	$(call cmd,csingle)

.lib/host_endian.h: ../src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../lib target=$(abspath .lib)/
ifeq ($(SGX), 1)
include $(addsuffix .manifest.sgx.d,$(executables))
endif
else
.IGNORE: $(executables)
$(executables):
endif

-include $(addsuffix .d, $(executables)) $(addsuffix .i.d, $(executables)) $(addsuffix .s.d, $(executables))

.PHONY: clean
clean:
	rm -rf pal_loader $(call expand_target,$(target)) .lib *.cached \
	       $(addsuffix .d, $(executables)) $(addsuffix .i.d, $(executables)) \
	       $(addsuffix .s.d, $(executables)) \
	       $(addsuffix .manifest.sgx.d,$(executables)) \
		   .output.*
