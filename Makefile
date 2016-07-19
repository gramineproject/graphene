SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all clean install

ifeq ($(SYS),x86_64-linux-gnu)
targets += pack
endif

.PHONY: $(targets)
$(targets):
	for d in Pal LibOS; \
	do \
		$(MAKE) -C $$d $@; \
	done
