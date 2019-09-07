include ../../../Makefile.configs

# SUBDIRS = regression native inline benchmark
SUBDIRS = native

.PHONY: all clean sgx-tokens
all clean sgx-tokens:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@; \
	done
