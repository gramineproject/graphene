include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -L../common \
          -D_GNU_SOURCE

LDLIBS += -lsgx_util

PREFIX ?= /usr/local

.PHONY: all
all: quote_dump

quote_dump: quote_dump.o
	$(call cmd,csingle)

.PHONY: install
install:
	install quote_dump ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o quote_dump

.PHONY: distclean
distclean: clean
