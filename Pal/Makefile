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

.PHONY: distclean
distclean: clean
