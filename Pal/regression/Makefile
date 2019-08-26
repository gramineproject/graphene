include ../src/Makefile.Host

CC	= gcc
CFLAGS	= -Wall -O2 -std=c11 -fno-builtin -nostdlib \
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

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

ifeq ($(DEBUG),1)
CC += -g
endif
export DEBUG

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

# To enable tests for remote attestation, please provide RA_CLIENT_SPID and RA_CLIENT_KEY
# in the environment variables.
# To obtain a SPID, register in the Intel API portal:
# https://api.portal.trustedservices.intel.com/EPID-attestation

manifest_rules = \
	-e 's:\$$(PAL):$(abspath ../../Runtime/pal_loader):g' \
	-e 's:\$$(PWD):$(shell pwd)/:g' \
	-e 's:\$$(RA_CLIENT_SPID):$(RA_CLIENT_SPID):g' \
	-e 's:\$$(RA_CLIENT_KEY):$(RA_CLIENT_KEY):g' \
	-e 's:\$$(RA_CLIENT_LINKABLE):$(if $(RA_CLIENT_LINKABLE),$(RA_CLIENT_LINKABLE),0):g' \
	$(extra_rules)

manifest: manifest.template
	$(call cmd,manifest,$(manifest_rules))

%.manifest: %.manifest.template $(executables) $(pal_lib)
	$(call cmd,manifest,$(manifest_rules))

../src/user_shared_start.o ../src/user_start.o: ../src/user_start.S
	$(MAKE) -C ../src $(notdir $@)

CFLAGS-AvxDisable += -mavx

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

ifeq ($(filter clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
ifeq ($(SGX), 1)
# Bootstrap5.manifest doesn't have main executable, but only preloaded
# libraries. Static pattern rule is needed to override the implicit pattern
# rule defined in Pal/src/host/Linux-SGX/Makefile.Test.
Bootstrap5.manifest.sgx.d: %.manifest.sgx.d: %.manifest
	$(call cmd,sgx_sign_depend)
include $(addsuffix .manifest.sgx.d,$(executables))
endif
endif

.lib/host_endian.h: ../src/host/$(PAL_HOST)/host_endian.h
	@mkdir -p .lib
	cp -f $< $@

$(graphene_lib): .lib/host_endian.h
	$(MAKE) -C ../lib target=$(abspath .lib)/

else
.IGNORE: $(preloads) $(executables)
$(preloads) $(executables):
endif

export PYTHONPATH=../../Scripts

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(call expand_target_to_token,$(target))
	python3 -m pytest --junit-xml $@ -v test_pal.py

.PHONY: clean
clean:
	rm -rf $(call expand_target,$(target)) $(preloads) *.tmp .lib *.cached *.sig *.d .output.* *.token .*.d .*.sig .*.token __pycache__ .cache pal-regression.xml
