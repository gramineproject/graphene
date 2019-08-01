include ../src/Makefile.Host

CC	= gcc
CFLAGS	= -Wall -O2 -std=c11 -fno-builtin -nostdlib -mavx \
	  -I../include/pal -I../lib

preloads    = $(patsubst %.c,%,$(wildcard *.so.c))
executables = $(filter-out $(preloads),$(patsubst %.c,%,$(wildcard *.c))) ..Bootstrap
manifests   = manifest $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))

target = $(executables) $(manifests)

graphene_lib = .lib/graphene-lib.a
pal_lib = ../../Runtime/libpal-$(PAL_HOST).so
headers = $(wildcard ../include/pal/*.h)

.PHONY: default
default: all
include ../src/Makefile.Test

RUNTIME_DIR = $(CURDIR)/../../Runtime

export PAL_LOADER = $(RUNTIME_DIR)/pal-$(PAL_HOST)
export PAL_SEC = $(RUNTIME_DIR)/pal_sec-$(PAL_HOST)

.PHONY: all
all: $(call expand_target,$(target)) $(preloads)

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
	-e 's:\$$(RA_CLIENT_LINKABLE):$(if,$(RA_CLIENT_LINKABLE),$(RA_CLIENT_LINKABLE),0):g' \
	$(extra_rules)

manifest: manifest.template
	sed $(manifest_rules) $< >$@

%.manifest: %.manifest.template $(executables) $(pal_lib)
	sed $(manifest_rules) $< >$@
	(grep -q "#\!" $@ && chmod +x $@) || true

../src/user_shared_start.o ../src/user_start.o: ../src/user_start.S
	$(MAKE) -C ../src $(notdir $@)

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)
$(preloads): %.so: %.so.c ../src/user_shared_start.o \
	$(graphene_lib) $(pal_lib) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) -shared -fPIC $(CFLAGS) $^ -o $@

$(executables): %: %.c ../src/user_start.o \
	$(graphene_lib) $(pal_lib) $(preloads) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $^ -o $@

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

PYTHONENV = "PYTHONPATH=../../Scripts"

ifeq ($(SGX_RUN),1)
	PYTHONENV += "TIMEOUT=20000"
endif

regression: $(call expand_target,$(target))
	@printf "\n\nBasic Bootstrapping:\n"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\nException Handling:\n"
	@for f in $(wildcard 01_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\nSingle-Process Functionalities:\n"
	@for f in $(wildcard 02_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\nProcess Creation:\n"
	@for f in $(wildcard 03_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\nMulti-Process Functionalities:\n"
	@for f in $(wildcard 04_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\nReference Monitor (Optional):\n"
	@for f in $(wildcard 05_*.py); do env $(PYTHONENV) python3 $$f || exit $$?; done
	@printf "\n\n"

.PHONY: clean
clean:
	rm -rf $(call expand_target,$(target)) $(preloads) *.tmp .lib *.cached *.sig
