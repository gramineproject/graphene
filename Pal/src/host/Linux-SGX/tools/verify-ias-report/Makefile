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
