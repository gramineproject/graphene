include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -D_GNU_SOURCE

LDLIBS += -L../common \
          -L../../../../../../common/src/crypto/mbedtls/install/lib \
          -lsgx_util -lmbedcrypto

PREFIX ?= /usr/local

.PHONY: all
all: quote_dump

quote_dump: quote_dump.o
	$(call cmd,csingle)

.PHONY: install
install:
	install -D quote_dump -t ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o quote_dump

.PHONY: distclean
distclean: clean
