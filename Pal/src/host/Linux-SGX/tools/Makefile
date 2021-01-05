include ../../../../../Scripts/Makefile.configs
include ../../../../../Scripts/Makefile.rules

targets = all clean distclean install

.PHONY: $(targets)
$(targets):
	$(MAKE) -C common $@
	$(MAKE) -C is-sgx-available $@
	$(MAKE) -C quote-dump $@
	$(MAKE) -C ias-request $@
	$(MAKE) -C verify-ias-report $@
	$(MAKE) -C ra-tls $@
	$(MAKE) -C pf_crypt $@
	$(MAKE) -C pf_tamper $@
