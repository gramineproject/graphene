include ../../../Makefile.configs
include ../../../Pal/src/Makefile.Host

# SUBDIRS = regression native inline benchmark
SUBDIRS = native

.PHONY: default
default: all

.PHONY: all clean
all clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
