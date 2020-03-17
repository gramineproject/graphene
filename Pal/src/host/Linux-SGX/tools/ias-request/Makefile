include ../../../../../../Scripts/Makefile.configs
CFLAGS += -I../.. -I../common -D_GNU_SOURCE
LDFLAGS += -L../common \
           -L../../../../../lib/crypto/mbedtls/install/lib

PREFIX ?= /usr/local

.PHONY: all
all: ias_request

ias_request: ias_request.o
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -lsgx_util -lmbedcrypto -o $@

.PHONY: install
install:
	cp -n ias_request ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o ias_request
