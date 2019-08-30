include ../../../Scripts/Makefile.configs
include ../../../Pal/src/Makefile.Host

# SUBDIRS = regression native inline benchmark
SUBDIRS = native fs

.PHONY: default
default: all

.PHONY: all clean sgx-tokens distclean
all clean sgx-tokens distclean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d $@ || exit 255; \
	done
