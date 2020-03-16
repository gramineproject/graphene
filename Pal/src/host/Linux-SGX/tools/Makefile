include ../../../../../Scripts/Makefile.configs

targets = all clean

.PHONY: $(targets)
$(targets):
	$(MAKE) -C quote-dump $@
	$(MAKE) -C is-sgx-available $@
