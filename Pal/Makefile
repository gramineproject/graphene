include src/Makefile.Host

DIRS = src test regression

.PHONY: all
all:
	$(MAKE) -C src

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C regression clean

.PHONY: test
test:
	$(MAKE) -C src test
	$(MAKE) -C test
	$(MAKE) -C regression

.PHONY: format
format:
	clang-format -i $(shell find . -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./lib/crypto/udivmodti4.c -prune -o \
	                               -path ./src/host/Linux-SGX/sgx-driver -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)
