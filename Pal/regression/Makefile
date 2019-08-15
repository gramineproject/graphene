include ../src/Makefile.Host

CC	= gcc
CFLAGS	= -Wall -O2 -std=c11 -fno-builtin -nostdlib -mavx \
	  -I../include/pal -I../lib -I../src

preloads    = $(patsubst %.c,%,$(wildcard *.so.c))
executables = $(filter-out $(preloads),$(patsubst %.c,%,$(wildcard *.c))) ..Bootstrap
manifests   = manifest $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))

target = $(executables) $(manifests)

graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so

.PHONY: default
default: all
include ../../Makefile.configs
include ../../Makefile.rules
include ../src/Makefile.Test

RUNTIME_DIR = $(CURDIR)/../../Runtime

export PAL_LOADER = $(RUNTIME_DIR)/pal-$(PAL_HOST)

.PHONY: all
all: $(call expand_target,$(target)) $(preloads)

ifeq ($(DEBUG),1)
CC += -g
endif
export DEBUG

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

manifest_rules = \
	-e 's:\$$(PAL):$(abspath ../../Runtime/pal_loader):g' \
	-e 's:\$$(PWD):$(shell pwd)/:g' \
	$(extra_rules)

manifest: manifest.template
	sed $(manifest_rules) $< >$@

%.manifest: %.manifest.template $(executables) $(pal_lib)
	sed $(manifest_rules) $< >$@
	(grep -q "#\!" $@ && chmod +x $@) || true

../src/user_shared_start.o ../src/user_start.o: ../src/user_start.S
	$(MAKE) -C ../src $(notdir $@)

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
LDLIBS-preloads = ../src/user_shared_start.o $(graphene_lib) $(pal_lib)
$(preloads): CFLAGS += -shared -fPIC
$(preloads): LDLIBS = $(LDLIBS-preloads)
$(preloads): %.so: %.so.c $(LDLIBS-preloads)
	$(call cmd,csingle)

LDLIBS-executables = ../src/user_start.o $(graphene_lib) $(pal_lib) $(preloads)
$(executables): CFLAGS += -no-pie
$(executables): LDLIBS = $(LDLIBS-executables)
$(executables): %: %.c $(LDLIBS-executables)
	$(call cmd,csingle)

include $(wildcard *.d)
ifeq ($(SGX), 1)
include $(addsuffix .manifest.sgx.d,$(executables))
endif

.lib/host_endian.h: ../src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../lib target=$(abspath .lib)/

Process2.manifest.sgx: Bootstrap.manifest.sgx

else
.IGNORE: $(preloads) $(executables)
$(preloads) $(executables):
endif

export PYTHONPATH=../../Scripts

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(call expand_target,$(target))
	python3 -m pytest --junit-xml $@ -v test_pal.py

.PHONY: clean
clean:
	rm -rf $(call expand_target,$(target)) $(preloads) *.tmp .lib *.cached *.sig *.d
