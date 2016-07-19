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

reldir = $(shell p=`dirname $(1)` ; d=; while [ "$$p" != "." ]; do p=`dirname $$p`; d=../$$d; done; echo $$d)

manifest_rules = \
	-e 's:\$$(PALDIR):$(PALDIR):g' \
	-e 's:\$$(PWD):$(PWD):g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMDIR):$(SHIMDIR):g' \
	-e 's:\$$(SHIMPATH):$(SHIMDIR)/libsysdb.so:g' \
	-e 's:\$$(LIBCDIR):$(LIBCDIR):g' \
	$(extra_rules)

%manifest: %manifest.template
	@echo [ $@ ]
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
