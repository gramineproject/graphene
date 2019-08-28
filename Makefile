-include build-config.mk

ifneq ($(BUILD_CONFIGURED),1)
$(error "Run ./build-setup to configure build before running make!")
endif

SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all format test sgx-tokens

ifneq ($(filter sgx-tokens,$(MAKECMDGOALS)),)
ifneq ($(SGX),1)
$(error "The 'sgx-tokens' target requires SGX=1")
endif
endif

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@

.PHONY: clean
clean:
	$(MAKE) -C Pal clean
	$(MAKE) -C LibOS clean
	$(MAKE) -C Runtime clean
	rm -f build-config.mk
