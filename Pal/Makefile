include ../Scripts/Makefile.configs

DIRS = src regression

.PHONY: all
all:
	$(MAKE) -C src

clean_targets = clean distclean
.PHONY: $(clean_targets)
$(clean_targets):
	$(MAKE) -C src $@
	$(MAKE) -C regression $@
	$(MAKE) -C lib $@

.PHONY: test
test:
	$(MAKE) -C src test
	$(MAKE) -C regression

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C regression sgx-tokens

.PHONY: format
format:
	clang-format -i $(shell find . -path ./lib/crypto/mbedtls -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON.c -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON.h -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON-*/cJSON.c -prune -o \
	                               -path ./src/host/Linux-SGX/tools/common/cJSON-*/cJSON.h -prune -o \
	                               \( -name '*.h' -o -name '*.c' \) -print)

.PHONY: distclean
distclean: clean
