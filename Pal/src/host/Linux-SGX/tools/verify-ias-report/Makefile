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
all: verify_ias_report

verify_ias_report: verify_ias_report.o
	$(call cmd,csingle)

.PHONY: install
install:
	install -D verify_ias_report -t ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o verify_ias_report

.PHONY: distclean
distclean: clean
