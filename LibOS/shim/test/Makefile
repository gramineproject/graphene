# SUBDIRS = regression native inline benchmark
SUBDIRS = native

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: default
default: all

.PHONY: all clean
all clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
