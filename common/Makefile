include ../Scripts/Makefile.configs

DIRS = src

.PHONY: all
all:
	$(MAKE) -C src

clean_targets = clean distclean
.PHONY: $(clean_targets)
$(clean_targets):
	$(MAKE) -C src $@

.PHONY: test
test:

.PHONY: sgx-tokens
sgx-tokens:
