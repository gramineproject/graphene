# SUBDIRS = regression native inline benchmark
SUBDIRS = native fs

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: default
default: all

.PHONY: all clean sgx-tokens
all clean sgx-tokens:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
