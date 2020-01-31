# SUBDIRS = regression native inline benchmark
SUBDIRS = native fs

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: default
default: all

.PHONY: all clean sgx-tokens distclean
all clean sgx-tokens distclean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@ || exit 255; \
	done
