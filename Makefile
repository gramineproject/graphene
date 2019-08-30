include Makefile.configs
include Pal/src/Makefile.Host

targets = all clean format test

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@
