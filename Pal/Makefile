include src/Makefile.Host

DIRS = src test regression

.PHONY: all clean
all clean:
	for d in $(DIRS); \
	do \
		$(MAKE) -C $$d $@ || exit $?; \
	done

.PHONY: test
test:
	$(MAKE) -C test test

.PHONY: format
format:
	clang-format -i $(shell find . -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./lib/crypto/udivmodti4.c -prune -o \
	                               -path ./src/host/Linux-SGX/sgx-driver -prune -o \
	                               -path ./src/security/Linux/bpf-helper.h -prune -o \
	                               -path ./src/security/Linux/bpf_helper.c -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: pack
pack:
	$(MAKE) -C test pack
	$(MAKE) -C regression pack
