subdirs = inline native benchmark regression apps

SYS ?= $(shell gcc -dumpmachine)
export SYS

CC = gcc
CXX = g++
CFLAGS 	= -std=gnu99 -I$(level)../include
CFLAGS-debug = $(CFLAGS) -I$(level)../../../Pal/lib \
	       -I$(level)../../../Pal/include/pal
LDFLAGS	=
LDFLAGS-debug = $(LDFLAGS) -L$(level)../src -L$(level)../../../Pal/src \
		-Wl,-rpath-link=$(abspath $(LEVEL)../src) \
		-Wl,-rpath-link=$(abspath $(level)../../../Pal/src) \
		-lpal -lsysdb_debug

libs = $(level)../src/libsysdb_debug.so $(level)../../../Pal/src/libpal.so
glibc_dir = $(level)../../build

all: $(target) $(if $(level),,build-subdirs)

debug: DEBUG=debug
debug: CC=gcc -g
debug: CXX=g++ -g
debug: $(target) $(if $(level),,build-subdirs)

manifest: manifest.template
	rm -rf $@
	cp $@.template $@

pal:
	[ ! -f $(level)../../../Pal/src/pal ] || ln -sf $(level)../../../Pal/src/pal pal

pal_sec:
	[ ! -f $(level)../../../Pal/src/pal_sec ] || ln -sf $(level)../../../Pal/src/pal_sec pal_sec

.PHONY: test clean

clean: $(clean-extra) $(if $(level),,clean-subdirs)
	rm -rf $(target)

build-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) $(DEBUG); cd ..); done

ifeq ($(SYS),x86_64-linux-gnu)
ifeq ($(level),)
.PHONY: pack
pack:
	for f in $(subdirs); do (cd $$f; $(MAKE) pack; cd ..); done
endif
endif

clean-subdirs:
	for f in $(subdirs); do (cd $$f; $(MAKE) clean; cd ..); done
