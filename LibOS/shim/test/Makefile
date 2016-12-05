subdirs = native

SYS ?= $(shell gcc -dumpmachine)
export SYS

PALDIR  = $(level)../../../Pal/src
SHIMDIR = $(level)../src
LIBCDIR = $(level)../../glibc-build

CC = gcc
CXX = g++
CFLAGS 	= -std=gnu99
CFLAGS-debug = $(CFLAGS) -I$(PALDIR)/../include/pal -I$(PALDIR)/../lib
LDFLAGS	=
LDFLAGS-debug = $(LDFLAGS) -L$(SHIMDIR) \
		-Wl,-rpath-link=$(abspath $(SHIMDIR)) \
		-Wl,-rpath-link=$(abspath $(PALDIR)) \
		-lpal -lsysdb_debug

default: all
include $(PALDIR)/Makefile.Test

all: $(target) $(if $(level),,build-subdirs) | $(call expand_target,$(exec_target))

ifeq ($(DEBUG),1)
CC += -g
CXX += -g
endif
export DEBUG

manifest_rules = \
	-e 's:\$$(PALDIR):'$$RELDIR'$(PALDIR):g' \
	-e 's:\$$(PWD):$(PWD):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMDIR):'$$RELDIR'$(SHIMDIR):g' \
	-e 's:\$$(SHIMPATH):'$$RELDIR'$(SHIMDIR)/libsysdb.so:g' \
	-e 's:\$$(LIBCDIR):'$$RELDIR'$(LIBCDIR):g' \
	$(extra_rules)

%manifest: %manifest.template
	@echo [ $@ ]
	RELDIR=$(filter-out ./,$(python -c "import os.path; print os.path.relpath($(abspath $(dir $@)) $(PWD))")) && \
	sed $(manifest_rules) $< > $@
	(grep -q '^#!' $@ && chmod +x $@) || true

manifest: manifest.template
	@echo [ $@ ]
	sed $(manifest_rules) $< > $@

pal pal_sec:
	ln -sf $(level)../../../Pal/src/$@ $@

.PHONY: test clean

clean: $(clean-extra) $(if $(level),,clean-subdirs)
	rm -rf $(call expand_target,$(exec_target)) $(target)

build-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE); cd ..); done

ifeq ($(SYS),x86_64-linux-gnu)
ifeq ($(level),)
.PHONY: pack
pack:
	for f in $(subdirs); do (cd $$f; $(MAKE) pack; cd ..); done
endif
endif

clean-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) clean; cd ..); done
