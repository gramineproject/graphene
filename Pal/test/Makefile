include ../src/Makefile.Host

CC	= gcc
CFLAGS	= -Wall -O2 -std=gnu99 -fgnu89-inline -fno-builtin -nostdlib \
	  -I../include/pal -I../lib

.PHONY: default
default: all
include ../src/Makefile.Test

executables = HelloWorld File Failure Thread Fork Event Process Exception \
	      Memory Pipe Tcp Udp Yield Broadcast Ipc Server Wait HandleSend \
	      Select Segment Sleep Cpuid Pie
manifests = manifest

target = $(executables) $(manifests)

graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so
headers = $(wildcard ../include/pal/*.h)

.PHONY: all
all:	pal_loader $(call expand_target,$(target))

ifeq ($(DEBUG),1)
CC += -g
endif
export DEBUG

pal_loader:
	ln -sf ../../Runtime/pal_loader

manifest: manifest.template
	cp -f $< $@

%.manifest: %.manifest.template
	cp -f $< $@

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(executables): %: %.c $(graphene_lib) $(pal_lib) ../src/user_start.o
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(if $(filter Pie,$@),-fPIC -pie,) $^ -o $@

.lib/host_endian.h: ../src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../lib target=$(abspath .lib)/
else
.IGNORE: $(executables)
$(executables):
endif

.PHONY: clean
clean:
	rm -rf pal_loader $(call expand_target,$(target)) .lib *.cached
