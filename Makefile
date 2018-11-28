SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean format

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@
	$(MAKE) -C Runtime $@

.PHONY: install
install:
	@echo "\"make install\" is deprecated. use \"make\" instead."
