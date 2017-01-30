SYS ?= $(shell gcc -dumpmachine)
export SYS

.SILENT:

targets = all clean

ifeq ($(SYS),x86_64-linux-gnu)
targets += pack
endif

.PHONY: $(targets)
$(targets):
	$(MAKE) -C Pal $@
	$(MAKE) -C LibOS $@

.PHONY: install
install:
	@echo "\"make install\" is deprecated. use \"make\" instead."
