include ../../Makefile.configs
include ../../Pal/src/Makefile.Host

MAKEFLAGS += --check-symlink-times

.PHONY: all
all:
	$(MAKE) -C src

.PHONY: test
test:
	$(MAKE) -C test

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C test sgx-tokens

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean

.PHONY: format
format:
	clang-format -i $(shell find . -path ./test/apps -prune -o \( -name '*.h' -o -name '*.c' \) -print)
