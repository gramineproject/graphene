include ../../../../../Scripts/Makefile.configs

targets = all clean install

.PHONY: $(targets)
$(targets):
	$(MAKE) -C common $@
	$(MAKE) -C is-sgx-available $@
	$(MAKE) -C quote-dump $@
	$(MAKE) -C ias-request $@
	$(MAKE) -C verify-ias-report $@
