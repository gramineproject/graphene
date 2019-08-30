include ../../../Makefile.configs
include ../../../Pal/src/Makefile.Host

# SUBDIRS = regression native inline benchmark
SUBDIRS = native

.PHONY: default
default: all

.PHONY: all clean sgx-tokens
all clean sgx-tokens:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
