include ../../../../../../Scripts/Makefile.configs
CFLAGS += -I../..

PREFIX ?= /usr/local

.PHONY: all
all: quote_dump

.PHONY: install
install:
	cp -n quote_dump ${PREFIX}/bin

.PHONY: clean
clean:
	$(RM) *.o quote_dump
