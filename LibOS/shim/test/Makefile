subdirs = native

SYS ?= $(shell gcc -dumpmachine)
export SYS

PALDIR  = $(level)../../../Pal/src
SHIMDIR = $(level)../src
RUNTIME = $(level)../../../Runtime

ifeq ($(SGX),1)
PAL_LOADER = pal_loader SGX
else
PAL_LOADER = pal_loader
endif

CC = gcc
CXX = g++
CFLAGS 	= -Wall -std=gnu99
CFLAGS-debug = -I$(SHIMDIR)/../include -I$(PALDIR)/../include/pal -I$(PALDIR)/../lib
CXXFLAGS = -Wall -std=c++14
CXXFLAGS-debug = -I$(SHIMDIR)/../include -I$(PALDIR)/../include/pal -I$(PALDIR)/../lib
LDFLAGS	=
LDFLAGS-debug = -L$(SHIMDIR) -L$(PALDIR) -Wl,-rpath-link=$(abspath $(RUNTIME))

CFLAGS-libos = -I$(SHIMDIR)/../include -L$(SHIMDIR)/../../glibc-build/libos

.PHONY: default
default: all

include $(level)../../../Makefile.configs
include $(level)../../../Makefile.rules
include $(PALDIR)/Makefile.Test

.PHONY: all
all: pal_loader $(target) $(if $(level),,build-subdirs) | $(call expand_target,$(exec_target))

.PHONY: sgx-tokens
sgx-tokens: $(if $(level),,sgx-tokens-subdirs) $(call expand_target_to_token,$(exec_target))

ifeq ($(DEBUG),1)
CC += -g
CXX += -g
endif
export DEBUG

ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

ifeq ($(ABSPATH_IN_MANIFEST),yes)
manifest_rules = \
	-e 's:\$$(PAL):$(abspath $(RUNTIME))/$(PAL_LOADER):g' \
	-e 's:\$$(PWD):$(PWD):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):$(abspath $(RUNTIME))/libsysdb.so:g' \
	-e 's:\$$(LIBCDIR):$(abspath $(RUNTIME)):g' \
	$(extra_rules)
else
manifest_rules= \
	-e 's:\$$(PAL):$(abspath $(RUNTIME))/$(PAL_LOADER):g' \
	-e 's:\$$(PWD):$(PWD):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):'$$RELDIR'$(RUNTIME)/libsysdb.so:g' \
	-e 's:\$$(LIBCDIR):'$$RELDIR'$(RUNTIME):g' \
	$(extra_rules)
endif

pal_loader:
	ln -sf $(RUNTIME)/pal_loader

relative-to = $(shell python -c "import os.path; print os.path.relpath(\"$(abspath $2)\",\"$(abspath $1)\")")

%manifest: %manifest.template
	@echo [ $@ ]
	RELDIR=$(filter-out ./,$(call relative-to,$(dir $@),$(shell pwd))/) && \
	sed $(manifest_rules) $< > $@
	(grep -q '^#!' $@ && chmod +x $@) || true

manifest: manifest.template
	@echo [ $@ ]
	sed $(manifest_rules) $< > $@

ifeq ($(SGX), 1)
include $(addsuffix .manifest.sgx.d,$(patsubst %.manifest,%,$(exec_target)))
endif

.PHONY: clean
clean: $(clean-extra) $(if $(level),,clean-subdirs)
	rm -rf pal_loader $(call expand_target,$(exec_target)) $(target) $(wildcard *.d)

.PHONY: build-subdirs
build-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE); cd ..); done

.PHONY: sgx-tokens-subdirs
sgx-tokens-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) sgx-tokens; cd ..); done

.PHONY: clean-subdirs
clean-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) clean; cd ..); done
