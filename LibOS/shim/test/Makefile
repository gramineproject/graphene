include ../../../Scripts/Makefile.configs

SUBDIRS = regression native fs inline benchmark

.PHONY: all clean sgx-tokens
all clean sgx-tokens:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@ || exit 255; \
	done
