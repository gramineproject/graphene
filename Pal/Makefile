include ../Scripts/Makefile.configs

DIRS = src crt_init regression

.PHONY: all
all:
	$(MAKE) -C src
	$(MAKE) -C crt_init

clean_targets = clean distclean
.PHONY: $(clean_targets)
$(clean_targets):
	$(MAKE) -C src $@
	$(MAKE) -C crt_init $@
	$(MAKE) -C regression $@
	$(MAKE) -C lib $@

.PHONY: test
test:
	$(MAKE) -C src test
	$(MAKE) -C crt_init test
	$(MAKE) -C regression

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C regression sgx-tokens

.PHONY: format
format:
	clang-format -i $(shell find . -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./lib/crypto/udivmodti4.c -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON.c -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON.h -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON-*/cJSON.c -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON-*/cJSON.h -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
