include Scripts/Makefile.configs

targets = all clean format test sgx-tokens distclean

ifneq ($(filter sgx-tokens,$(MAKECMDGOALS)),)
ifneq ($(SGX),1)
$(error "The 'sgx-tokens' target requires SGX=1")
endif
endif

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Scripts $@
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@
	$(MAKE) -C Tools $@
	@echo
	@echo NOTE: We arere in the middle of transision to meson build system.
	@echo You have sucessfully built Graphene, now please install Graphene using meson.
	@echo See https://graphene.readthedocs.io/en/latest/building.html for more details.
	@echo
