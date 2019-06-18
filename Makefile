SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean format test

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@
