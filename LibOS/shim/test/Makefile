SUBDIRS = regression native benchmark
## inline directory doesn't build. skip it for now.
# SUBDIRS += inline

SYS ?= $(shell gcc -dumpmachine)
export SYS

.PHONY: default
default: all

.PHONY: all clean test
all clean test:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
