include ../../../Scripts/Makefile.configs

SUBDIRS = regression fs

.PHONY: all clean sgx-tokens distclean
all clean sgx-tokens distclean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@ || exit 255; \
	done
