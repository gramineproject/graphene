MAKEFLAGS += --check-symlink-times

SYS ?= $(shell gcc -dumpmachine)
export SYS

targets = all debug clean
ifeq ($(SYS),x86_64-linux-gnu)
targets += pack
endif

.PHONY: $(targets)
$(targets): src test
	for d in src test; \
	do \
		make $@ -C $$d; \
	done
