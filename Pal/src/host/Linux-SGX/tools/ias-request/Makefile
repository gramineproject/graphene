include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -L../common \
          -L../../../../../lib/crypto/mbedtls/install/lib \
          -D_GNU_SOURCE

LDLIBS += -lsgx_util -lmbedcrypto

PREFIX ?= /usr/local

.PHONY: all
all: ias_request

ias_request: ias_request.o
	$(call cmd,csingle)

.PHONY: install
install:
	install -D ias_request -t ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o ias_request

.PHONY: distclean
distclean: clean
