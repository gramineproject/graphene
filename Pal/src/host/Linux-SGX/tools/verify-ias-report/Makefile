include ../../../../../../Scripts/Makefile.configs
include ../../../../../../Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../common \
          -L../common \
          -D_GNU_SOURCE

LDLIBS += -lsgx_util

PREFIX ?= /usr/local

.PHONY: all
all: verify_ias_report

verify_ias_report: verify_ias_report.o
	$(call cmd,csingle)

.PHONY: install
install:
	install verify_ias_report ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o verify_ias_report
