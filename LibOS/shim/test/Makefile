subdirs = inline native apps

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

all: $(targets) $(if $(level),,build-subdirs)

debug: DEBUG=debug
debug: CC=gcc -g
debug: CXX=g++ -g
debug: $(targets) $(if $(level),,build-subdirs)

$(subdirs): %:
	cd $@ && make

manifest: manifest.template
	rm -rf $@
	cp $@.template $@

pal:
	[ ! -f $(level)../../../Pal/src/pal ] || ln -sf $(level)../../../Pal/src/pal pal

pal_sec:
	[ ! -f $(level)../../../Pal/src/pal_sec ] || ln -sf $(level)../../../Pal/src/pal_sec pal_sec

# Regression Test
rtest:	$(rtarget)
	for d in $(rtarget); \
	do \
		make run-$$d || return $$?; \
	done

.PHONY: test rtest clean

$(patsubst %,run-%,$(rtarget)): run-%: %
	@echo [ run $< $(value arg-$<) ]
	@./libpal.so $< $(value arg-$<) > OUTPUT 2> ERROR
	@$(value test-$<)
	@rm -rf OUTPUT ERROR

clean: $(clean-extra) $(if $(level),,clean-subdirs)
	rm -rf $(targets)

build-subdirs:
	for f in $(subdirs); do (cd $$f; make $(DEBUG); cd ..); done

clean-subdirs:
	for f in $(subdirs); do (cd $$f; make clean; cd ..); done
