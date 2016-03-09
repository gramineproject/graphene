SYS ?= $(shell gcc -dumpmachine)
export SYS

apps = lmbench gcc busybox lighttpd bash apache make python r openjdk
packed_apps = lmbench

target = pal pal_sec
clean-extra = clean-all

level = ../
include ../Makefile

ifeq ($(SYS),x86_64-linux-gnu)
HOSTDIR =
PAL = $(abspath $(PWD)/../pal_loader)
else
HOSTDIR = /tmp/host
PAL = $(abspath $(PWD)/../pal)
endif

manifest_rules = \
	-e 's:\$$(PAL):$(PAL):g' \
	-e 's:\$$(PWD):$(PWD)/:g' \
	-e 's:\$$(BIN):$(subst .manifest,,$(notdir $@)):g' \
	-e 's:\$$(SHIMPATH):$(abspath ../../src/libsysdb.so):g' \
	-e 's:\$$(GLIBCDIR):$(abspath $(glibc_dir))/:g' \
	-e 's:\$$(HOSTDIR):$(HOSTDIR):g' \
	$(extra_rules)

%.manifest: %.manifest.template
	sed $(manifest_rules) $< >$@
	chmod +x $@

ifeq ($(SYS),x86_64-linux-gnu)
build-all:
	for f in $(apps); do (cd $$f; $(MAKE) $(DEBUG) || true; cd ..); done

.PHONY: pack
pack:
	for f in $(packed_apps); do (cd $$f; $(MAKE) pack; cd ..); done
else
build-all:
	for f in $(packed_apps); do (cd $$f; $(MAKE) || true; cd ..); done
endif

clean-all:
	for f in $(apps); do (cd $$f; $(MAKE) clean; cd ..); done
