include ../Makefile.configs

DIRS = src csu test regression

.PHONY: all
all:
	$(MAKE) -C src
	$(MAKE) -C csu

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C csu clean
	$(MAKE) -C test clean
	$(MAKE) -C regression clean

.PHONY: test
test:
	$(MAKE) -C src test
	$(MAKE) -C csu test
	$(MAKE) -C test
	$(MAKE) -C regression

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C test sgx-tokens
	$(MAKE) -C regression sgx-tokens

.PHONY: format
format:
	clang-format -i $(shell find . -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./lib/crypto/udivmodti4.c -prune -o \
	                               -path ./src/host/Linux-SGX/sgx-driver -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)
