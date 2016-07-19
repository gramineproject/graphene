SYS ?= $(shell gcc -dumpmachine)

CC	= gcc
CFLAGS	= -Wall -O2 -std=gnu99 -fgnu89-inline -fno-builtin -nostdlib \
	  -I../include/pal -I../lib

preloads    = $(patsubst %.c,%,$(wildcard *.so.c))
executables = $(filter-out $(preloads),$(patsubst %.c,%,$(wildcard *.c)))
manifests   = manifest $(patsubst %.manifest.template,%.manifest,$(wildcard *.manifest.template))

target = $(executables) $(manifests)

graphene_lib = .lib/graphene-lib.a
pal_lib = ../src/libpal.so
headers = $(wildcard ../include/pal/*.h)

default: all
include ../src/Makefile.Test

all: $(call expand_target,$(target)) $(preloads)

ifeq ($(DEBUG),1)
CC += -g
endif
export DEBUG

manifest_rules = \
	-e 's:\$$(PAL):$(abspath ../src/pal):g' \
	-e 's:\$$(PWD):$(shell pwd)/:g' \
	$(extra_rules)

manifest: manifest.template
	sed $(manifest_rules) $< >$@

%.manifest: %.manifest.template
	sed $(manifest_rules) $< >$@
	(grep -q "#\!" $@ && chmod +x $@) || true

../src/user_shared_start.o ../src/user_start.o: ../src/user_start.S
	$(MAKE) -C ../src $(notdir $@)

ifeq ($(SYS),x86_64-linux-gnu)
$(preloads): %.so: %.so.c ../src/user_shared_start.o \
	$(graphene_lib) $(pal_lib) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) -shared -fPIC $(CFLAGS) $^ -o $@

$(executables): %: %.c ../src/user_start.o \
	$(graphene_lib) $(pal_lib) $(preloads) ../include/pal/pal.h
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $^ -o $@

$(graphene_lib):
	$(MAKE) -C ../lib target=$(shell pwd)/.lib/

.PHONY: pack
pack: $(preloads) $(executables)
	@../../Scripts/pack_binaries.sh test $^
else
$(preloads) $(executables): .packed/test.tar.gz
	tar -xmozf $< $@
endif

PYTHONENV = "PYTHONPATH=../../Scripts"

ifeq ($(SGX_RUN),1)
	PYTHONENV += "TIMEOUT=5000"
endif

regression: $(call expand_target,$(target))
	@printf "\n\nBasic Bootstrapping:\n"
	@for f in $(wildcard 00_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\nException Handling:\n"
	@for f in $(wildcard 01_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\nSingle-Process Functionalities:\n"
	@for f in $(wildcard 02_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\nProcess Creation:\n"
	@for f in $(wildcard 03_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\nMulti-Process Functionalities:\n"
	@for f in $(wildcard 04_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\nReference Monitor (Optional):\n"
	@for f in $(wildcard 05_*.py); do env $(PYTHONENV) python $$f; done
	@printf "\n\n"

clean:
	rm -rf $(call expand_target,$(target)) $(preloads) *.tmp .lib *.cached
