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
	@echo NOTE: We are in the middle of a transition to the Meson buildsystem.
	@echo You have successfully built Graphene, now please install Graphene using Meson.
	@echo See https://graphene.readthedocs.io/en/latest/building.html for more details.
	@echo '(For now, please ignore "Build targets in project: 0" and "ninja: no work to do.")'
	@echo
