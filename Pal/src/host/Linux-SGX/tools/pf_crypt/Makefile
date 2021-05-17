include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -I../../protected-files \
          -D_GNU_SOURCE

LDLIBS += -L../common \
          -L../../../../../../common/src/crypto/mbedtls/install/lib \
          -lsgx_util -lmbedcrypto

PREFIX ?= /usr/local

pf_crypt: pf_crypt.o
	$(call cmd,csingle)

.PHONY: all
all: pf_crypt

.PHONY: install
install:
	install -D pf_crypt -t ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o pf_crypt

.PHONY: distclean
distclean: clean
