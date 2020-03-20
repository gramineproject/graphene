include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
		  -I../common \
		  -D_GNU_SOURCE

LDFLAGS += -L../common \
           -L../../../../../lib/crypto/mbedtls/install/lib

LDLIBS-ias_request += -lsgx_util

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
