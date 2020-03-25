include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -L../common \
          -D_GNU_SOURCE

LDLIBS += -lsgx_util

PREFIX ?= /usr/local

.PHONY: all
all: ias_request

ias_request: ias_request.o
	$(call cmd,csingle)

.PHONY: install
install:
	install ias_request ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o ias_request

.PHONY: distclean
distclean: clean
